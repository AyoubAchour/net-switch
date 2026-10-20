package stack_test

import (
	"bytes"
	"crypto/sha256"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func awaitSendBuffer(t testing.TB, ep *tcp.Endpoint, size int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, used := ep.BufferUsage(); used == size {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("download did not reach the send buffer")
		}
		runtime.Gosched()
	}
}

func TestCloseDownloadACKStaysAsync(t *testing.T) {
	o := ns.DefaultOptions()
	o.Clock = faketime.NewManualClock()
	p := newPeerOptions(t, false, flows.Defaults(), o)
	p.fixedSendBuffer = 6 << 20
	p.open(1000)
	p.upload([]byte("request"))
	ep := p.endpoint()
	ep.SocketOptions().SetSendBufferSize(6<<20, true)
	p.inject(p.windowACK(0))
	p.inject(p.packet(p.seq+1, p.ack, header.TCPFlagRst|header.TCPFlagAck, nil))
	done := make(chan error, 1)
	go func() {
		_, err := p.current.conn.Write(bytes.Repeat([]byte{42}, 5<<20))
		p.current.conn.CloseWrite()
		done <- err
	}()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	closeSignal(t, p.current.sentEOF, "download CloseWrite")
	if state := tcp.EndpointState(ep.State()); state != tcp.StateFinWait1 {
		t.Fatal("download is not closing", state)
	}
	p.stack.Pause()
	defer p.stack.Resume()
	sent := p.stack.Stats().TCP.SegmentsSent.Value()
	p.inject(p.windowACK(65535))
	// No sleeps or timing threshold: the only processor capable of sending
	// the queued download is paused. The TUN reader must leave it queued.
	if got := p.stack.Stats().TCP.SegmentsSent.Value(); got != sent {
		t.Fatalf("TUN reader transmitted %d download segments", got-sent)
	}
	if p.table.Stats().Flows != 1 || p.stack.Stats().TCP.ResetsSent.Value() != 0 {
		t.Fatal("live download under-counted or reset", p.diagnostics())
	}
}

// Transfer and hash 100 MB through the relay. Queue and drain two 5 MiB tails,
// first while ESTABLISHED, then after CloseWrite (FIN_WAIT_1). Keep the same
// connections and stack: gVisor randomizes TCP worker assignment per stack,
// which would otherwise confound the latency comparison.
func BenchmarkCloseDownloadOtherFlow(b *testing.B) {
	b.Run("paired", func(b *testing.B) {
		var latency [2][]time.Duration
		for range b.N {
			pair := downloadWithOtherFlow(b)
			for i := range pair {
				latency[i] = append(latency[i], pair[i]...)
			}
		}
		b.SetBytes(100_000_000)
		for i, name := range []string{"open", "closing"} {
			samples := latency[i]
			slices.Sort(samples)
			if samples[len(samples)/2] <= 0 {
				b.Fatal("clock cannot resolve the other flow's latency")
			}
			b.ReportMetric(float64(samples[len(samples)/2].Nanoseconds()), name+"-p50-ns")
			b.ReportMetric(float64(samples[(len(samples)-1)*99/100].Nanoseconds()), name+"-p99-ns")
			b.ReportMetric(float64(samples[len(samples)-1].Nanoseconds()), name+"-max-ns")
		}
	})
}

func downloadWithOtherFlow(t testing.TB) [2][]time.Duration {
	p := newPeer(t, false)
	p.fixedSendBuffer = 6 << 20
	p.open(1000)
	p.upload([]byte("download"))
	other := &peer{t: t, link: p.link, stack: p.stack, accepted: p.accepted, table: p.table, config: p.config, port: p.port + 1, forward: p.forward}
	other.open(2000)
	other.upload([]byte("ready"))
	ep := p.endpoint()
	ep.SocketOptions().SetSendBufferSize(6<<20, true)
	const total, tail = 100_000_000, 5 << 20
	const prefix = total - 2*tail
	clock := newLatencyClock(t)
	block := bytes.Repeat([]byte{0x5a}, 32<<10)
	resume := make(chan struct{})
	defer close(resume)
	writer := make(chan error, 1)
	remote := p.current.conn
	go func() {
		for phase, size := range []int{prefix, tail, tail} {
			if phase != 0 {
				<-resume
			}
			for left := size; left > 0; {
				n := min(left, len(block))
				if _, err := remote.Write(block[:n]); err != nil {
					writer <- err
					return
				}
				left -= n
			}
		}
		remote.CloseWrite()
		writer <- nil
	}()
	hash := sha256.New()
	received, packets := 0, 0
	phase := -1
	var latency [2][]time.Duration
	for received < total {
		h := p.read(5 * time.Second)
		if h == nil || h.Flags().Contains(header.TCPFlagRst) {
			t.Fatal("download stalled or reset", p.diagnostics())
		}
		if h.DestinationPort() != p.port {
			continue
		}
		data := h[h.DataOffset():]
		if len(data) == 0 || h.SequenceNumber() != p.ack {
			continue
		}
		hash.Write(data)
		received += len(data)
		p.ack += uint32(len(data))
		boundary := received == prefix || received == prefix+tail
		if boundary {
			p.inject(p.windowACK(0))
			p.inject(p.packet(p.seq+1, p.ack, header.TCPFlagRst|header.TCPFlagAck, nil))
			resume <- struct{}{}
			phase++
			if phase == 1 {
				if err := <-writer; err != nil {
					t.Fatal(err)
				}
				closeSignal(t, p.current.sentEOF, "closing download tail")
			} else {
				awaitSendBuffer(t, ep, tail)
			}
			want := tcp.StateEstablished
			if phase == 1 {
				want = tcp.StateFinWait1
			}
			if state := tcp.EndpointState(ep.State()); state != want {
				t.Fatal("wrong download state", state, want)
			}
		}
		ack := p.windowACK(65535)
		if phase >= 0 && (boundary || packets%16 == 0) {
			start := clock()
			p.inject(ack)
			other.upload([]byte("ping"))
			latency[phase] = append(latency[phase], clock()-start)
		} else {
			p.inject(ack)
		}
		packets++
	}
	expected := sha256.New()
	for left := total; left > 0; {
		n := min(left, len(block))
		expected.Write(block[:n])
		left -= n
	}
	if !bytes.Equal(hash.Sum(nil), expected.Sum(nil)) {
		t.Fatal("100 MB download hash mismatch")
	}
	h := p.wait(header.TCPFlagFin)
	p.ack = h.SequenceNumber() + 1
	p.inject(p.packet(p.seq, p.ack, header.TCPFlagFin|header.TCPFlagAck, nil))
	p.seq++
	other.closeActive()
	if p.stack.Stats().TCP.ResetsSent.Value() != 0 {
		t.Fatal("download benchmark sent a reset")
	}
	// Drop the closed TCP graph now, not at the end of a multi-iteration bench.
	p.forward.Stop()
	p.stack.Close()
	p.stack.Wait()
	p.forward.Wait()
	p.link.Close()
	return latency
}
