package stack

import (
	"bytes"
	"fmt"
	"io"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestTimeWaitImmediateReuse(t *testing.T) {
	for _, timestamps := range []bool{false, true} {
		t.Run(fmt.Sprintf("timestamps=%t", timestamps), func(t *testing.T) {
			p := newPeer(t, timestamps)
			var slowest time.Duration
			for i := range 1000 {
				d := p.open(uint32(1000 + i*10000))
				if d > slowest {
					slowest = d
				}
				p.upload([]byte(fmt.Sprintf("flow %d", i)))
				p.closeActive()
			}
			t.Logf("1,000 reuses, slowest handshake %s", slowest)
			if slowest > 100*time.Millisecond {
				t.Fatal("reuse stalled over 100 ms")
			}
			if p.dials.Load() != 1000 {
				t.Fatal("unexpected outbound dial")
			}
		})
	}
}

func TestTimeWaitReuseDelays(t *testing.T) {
	for _, delay := range []time.Duration{0, 10 * time.Millisecond, 100 * time.Millisecond, 500 * time.Millisecond} {
		t.Run(delay.String(), func(t *testing.T) {
			p := newPeer(t, true)
			p.open(1000)
			p.upload([]byte("old"))
			p.closeActive()
			time.Sleep(delay)
			if d := p.open(10000); d > 100*time.Millisecond {
				t.Fatalf("reuse took %s", d)
			}
			p.upload([]byte("new"))
			p.closeActive()
		})
	}
}

func TestTimeWaitSequenceWrap(t *testing.T) {
	p := newPeer(t, false)
	p.open(^uint32(0) - 32)
	p.upload(bytes.Repeat([]byte{0xa5}, 100))
	p.closeActive()
	p.open(500)
	p.upload([]byte("after wrap"))
	p.closeActive()
}

func TestTimeWaitAfter100MB(t *testing.T) {
	if testing.Short() {
		t.Skip("100 MB gate runs in CI")
	}
	p := newPeer(t, true)
	p.open(1000)
	block := bytes.Repeat([]byte{1, 2, 3, 4}, 2048)
	for left := 100_000_000; left > 0; {
		n := min(left, len(block))
		p.upload(block[:n])
		left -= n
	}
	p.closeActive()
	p.open(200_000_000)
	p.upload([]byte("after 100 MB"))
	p.closeActive()
}

func TestTimeWaitDelayedSegmentsAndReordering(t *testing.T) {
	for _, timestamps := range []bool{false, true} {
		t.Run(fmt.Sprintf("timestamps=%t", timestamps), func(t *testing.T) {
			p := newPeer(t, timestamps)
			p.open(1000)
			syn := p.syn
			data := p.upload([]byte("stale payload"))
			rst := p.packet(p.seq, p.ack, header.TCPFlagRst|header.TCPFlagAck, nil)
			p.closeActive()
			p.open(100000)
			// Reordered local queues deliver RST, data, then SYN from the old flow.
			p.inject(rst)
			p.inject(data)
			p.inject(syn)
			p.upload([]byte("fresh payload"))
			p.closeActive()
			if p.dials.Load() != 2 {
				t.Fatal("old SYN caused another dial")
			}
		})
	}
}

func TestTimeWaitCandidateFailsLostFinalACK(t *testing.T) {
	p := newPeer(t, false)
	p.open(1000)
	p.upload([]byte("before lost ACK"))
	fin := p.closeActive() // The driver consumes, but the simulated app loses, our ACK.
	p.inject(fin)          // LAST_ACK retransmits its FIN.
	h := p.read(time.Second)
	if h == nil || !h.Flags().Contains(header.TCPFlagRst) {
		t.Fatal("candidate behavior changed; rerun the complete TIME_WAIT gate")
	}
	t.Log("GATE FAILED: timeout 0 resets the app in LAST_ACK after loss of our final ACK")
}

func TestTimeWaitCandidateFailsOverlappingSequenceSpaces(t *testing.T) {
	p := newPeer(t, false)
	p.open(1000)
	old := p.upload([]byte("OLD!"))
	p.closeActive()
	p.open(1000)
	// A genuinely fresh connection can overlap an old sequence space when
	// timestamps are absent. The old ACK is outside the new send window.
	p.inject(old)
	p.inject(p.packet(p.seq, p.ack, header.TCPFlagAck|header.TCPFlagPsh, []byte("NEW!")))
	got := make([]byte, 4)
	if _, err := io.ReadFull(p.current.conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "OLD!" {
		t.Fatalf("candidate behavior changed (%q); rerun complete TIME_WAIT gate", got)
	}
	t.Log("GATE FAILED: timeout 0 delivered old payload into a new connection without timestamps")
	p.current.conn.Close()
}
