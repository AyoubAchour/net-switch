package stack_test

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// Block after the app can see the packet but before the old endpoint can
// finish its transition. The output queue itself remains nonblocking.
type closeWireBarrier struct {
	flags            header.TCPFlags
	port             uint16
	entered, release chan struct{}
	once             sync.Once
}

type closeWireLink struct {
	*ns.Link
	barrier atomic.Pointer[closeWireBarrier]
}

func (l *closeWireLink) WritePackets(pkts gv.PacketBufferList) (int, tcpip.Error) {
	n, err := l.Link.WritePackets(pkts)
	if b := l.barrier.Load(); b != nil {
		for _, pkt := range pkts.AsSlice() {
			h := header.TCP(pkt.TransportHeader().Slice())
			if h.DestinationPort() == b.port && h.Flags().Contains(b.flags) {
				b.once.Do(func() { close(b.entered); <-b.release })
			}
		}
	}
	return n, err
}

func (p *peer) endpoint() *tcp.Endpoint {
	p.t.Helper()
	id := gv.TransportEndpointID{LocalAddress: remoteAddr, LocalPort: 443, RemoteAddress: appAddr, RemotePort: p.port}
	ep, ok := p.stack.FindTransportEndpoint(header.IPv4ProtocolNumber, tcp.ProtocolNumber, id, ns.NIC).(*tcp.Endpoint)
	if !ok {
		p.t.Fatal("missing endpoint", p.diagnostics())
	}
	return ep
}

func closeSignal(t testing.TB, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout: " + what)
	}
}

func (p *peer) receiveEOF() {
	p.t.Helper()
	var b [1]byte
	if n, err := p.current.conn.Read(b[:]); n != 0 || err != io.EOF {
		p.t.Fatalf("remote EOF: n=%d err=%v", n, err)
	}
}

// Return the final ACK without injecting it. A paused processor then makes
// the race with admission deterministic, independent of the 250 ms sweep.
func (p *peer) prepareFinalACK(simultaneous bool) []byte {
	p.t.Helper()
	ep := p.endpoint()
	skipped := p.table.Stats().TimeWaitSkipped
	if simultaneous {
		p.current.conn.CloseWrite()
		h := p.wait(header.TCPFlagFin)
		finACK := h.SequenceNumber() + 1
		p.inject(p.packet(p.seq, p.ack, header.TCPFlagFin|header.TCPFlagAck, nil))
		p.seq++
		for p.wait(header.TCPFlagAck).AckNumber() != p.seq {
		}
		p.ack = finACK
	} else {
		p.inject(p.packet(p.seq, p.ack, header.TCPFlagFin|header.TCPFlagAck, nil))
		p.seq++
		p.receiveEOF()
		p.current.conn.CloseWrite()
		h := p.wait(header.TCPFlagFin)
		p.ack = h.SequenceNumber() + 1
	}
	closeSignal(p.t, p.current.sentEOF, "relay CloseWrite returned")
	ep.LockUser()
	state := tcp.EndpointState(ep.State())
	ep.UnlockUser()
	want := tcp.StateLastAck
	if simultaneous {
		want = tcp.StateClosing
	}
	if p.table.Stats().TimeWaitSkipped > skipped {
		want = tcp.StateError
		if h := readCloseReset(p.t, p); h.SequenceNumber() != p.ack {
			p.t.Fatal("overflow reset has the wrong sequence")
		}
	}
	if state != want {
		p.t.Fatalf("close state=%s want=%s", state, want)
	}
	return p.packet(p.seq, p.ack, header.TCPFlagAck, nil)
}

func TestCloseAdmission(t *testing.T) {
	for _, budget := range []string{"total", "app", "unknown"} {
		for _, path := range []string{"app_fin", "remote_fin", "simultaneous", "app_rst", "remote_rst", "policy"} {
			t.Run(budget+"/"+path, func(t *testing.T) {
				limits := flows.Defaults()
				switch budget {
				case "total":
					limits.Flows = 1
				case "app":
					limits.PerApp = 1
				case "unknown":
					limits.Unknown = 1
				}
				link := &closeWireLink{Link: ns.NewLink()}
				p := newPeerLink(t, false, limits, ns.DefaultOptions(), link.Link, link)
				if budget == "unknown" {
					p.owners.Value.AppID = ""
				}
				p.open(1000)
				p.upload([]byte("old"))
				oldEndpoint := p.endpoint()
				if g := p.table.Stats(); g.Flows != 1 || g.Handshakes != 0 {
					t.Fatal("old connection must occupy its slot before closing", g)
				}
				releaseCleanup := p.holdRelayCleanup()
				defer releaseCleanup()
				old := p.current
				var resume func()
				switch path {
				case "app_fin", "remote_fin", "simultaneous", "app_rst":
					var last []byte
					switch path {
					case "app_rst":
						last = p.packet(p.seq, p.ack, header.TCPFlagRst|header.TCPFlagAck, nil)
					case "remote_fin":
						p.current.conn.CloseWrite()
						h := p.wait(header.TCPFlagFin)
						p.ack = h.SequenceNumber() + 1
						p.inject(p.packet(p.seq, p.ack, header.TCPFlagAck, nil))
						last = p.packet(p.seq, p.ack, header.TCPFlagFin|header.TCPFlagAck, nil)
					default:
						last = p.prepareFinalACK(path == "simultaneous")
					}
					p.stack.Pause()
					resume = sync.OnceFunc(p.stack.Resume)
					defer resume()
					p.inject(last)
				case "remote_rst", "policy":
					b := &closeWireBarrier{flags: header.TCPFlagRst, port: p.port, entered: make(chan struct{}), release: make(chan struct{})}
					resume = sync.OnceFunc(func() { close(b.release) })
					defer resume()
					link.barrier.Store(b)
					if path == "remote_rst" {
						p.current.conn.Abort(errors.New("remote reset"))
					} else {
						result, err := p.table.CloseFlows(flows.Selector{Line: p.config.AppLines["peer"]}, 0)
						// Unknown owners use the main line.
						if budget == "unknown" {
							result, err = p.table.CloseFlows(flows.Selector{Line: "A"}, 0)
						}
						if err != nil || result.Closed != 1 {
							t.Fatal("policy close", result, err)
						}
					}
					closeSignal(t, b.entered, "outgoing reset")
					h := p.read(time.Second)
					for h != nil && !h.Flags().Contains(header.TCPFlagRst) {
						h = p.read(time.Second)
					}
					if h == nil {
						t.Fatal("missing close reset")
					}
				}
				if g := p.table.Stats(); g.Flows != 0 {
					t.Error("close retained admission", p.diagnostics())
				}
				p.port++
				p.open(500)
				resume()
				releaseCleanup()
				old.conn.Close()
				p.upload([]byte("replacement"))
				p.closeActive()
				// The reset was visible before the paused writer returned. Its
				// counter increments inside that endpoint's critical section;
				// finish it only after proving replacement admission succeeded.
				oldEndpoint.LockUser()
				oldEndpoint.UnlockUser()
				if g := p.table.Stats(); g.Rejected != 0 || g.Admitted != 2 || p.dials.Load() != 2 {
					t.Fatal("false close rejection", p.diagnostics())
				}
				wantResets := uint64(0)
				if path == "remote_rst" || path == "policy" {
					wantResets = 1
				}
				if got := p.stack.Stats().TCP.ResetsSent.Value(); got != wantResets {
					t.Fatalf("stack resets=%d want=%d; %s", got, wantResets, p.diagnostics())
				}
			})
		}
	}
}

func TestCloseIdleAdmission(t *testing.T) {
	clock := faketime.NewManualClock()
	o := ns.DefaultOptions()
	o.Clock = clock
	limits := flows.Defaults()
	limits.Flows = 1
	p := newPeerOptions(t, false, limits, o)
	p.open(1000)
	p.upload([]byte("old"))
	// Keep the monitor from releasing the ticket, even on a slow machine.
	gate := make(chan struct{})
	p.relayCloseGate.Store(&gate)
	unblock := sync.OnceFunc(func() { p.relayCloseGate.Store(nil); close(gate) })
	defer unblock()
	ep := p.endpoint()
	idle, interval := tcpip.KeepaliveIdleOption(time.Second), tcpip.KeepaliveIntervalOption(time.Second)
	if err := ep.SetSockOpt(&idle); err != nil {
		t.Fatal(err)
	}
	if err := ep.SetSockOpt(&interval); err != nil {
		t.Fatal(err)
	}
	if err := ep.SetSockOptInt(tcpip.KeepaliveCountOption, 1); err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Second)
	p.wait(header.TCPFlagAck) // Do not answer the keepalive.
	clock.Advance(time.Second)
	if tcp.EndpointState(ep.State()) != tcp.StateError {
		t.Fatal("idle did not time out", p.diagnostics())
	}
	if g := p.table.Stats(); g.Flows != 0 {
		t.Fatal("timer removal retained admission until another SYN", g)
	}
	// Timer removal already released admission; a SYN does no reclaim work.
	p.port++
	p.open(500)
	unblock()
	p.upload([]byte("replacement"))
	p.closeActive()
	if p.table.Stats().Rejected != 0 || p.stack.Stats().TCP.ResetsSent.Value() != 0 {
		t.Fatal(p.diagnostics())
	}
}

func TestCloseFINWithoutPolicy(t *testing.T) {
	for _, active := range []bool{false, true} {
		name := "established"
		if active {
			name = "fin_wait_2"
		}
		t.Run(name, func(t *testing.T) {
			link := &finalACKLink{Link: ns.NewLink()}
			p := newPeerLink(t, false, flows.Defaults(), ns.DefaultOptions(), link.Link, link)
			p.open(1000)
			p.upload([]byte("old"))
			ep := p.endpoint()
			ep.SetTimeWaitPolicy(nil, nil)
			tcp.SetTimeWaitHandler(p.stack, nil)
			tcp.SetLocalCloseFence(p.stack, false)
			want := tcp.StateEstablished
			if active {
				p.current.conn.CloseWrite()
				h := p.wait(header.TCPFlagFin)
				p.ack = h.SequenceNumber() + 1
				p.inject(p.packet(p.seq, p.ack, header.TCPFlagAck, nil))
				// A challenge RST drains the ACK without closing the endpoint.
				tcp.SetLocalCloseFence(p.stack, true)
				p.inject(p.packet(p.seq+1, p.ack, header.TCPFlagRst|header.TCPFlagAck, nil))
				tcp.SetLocalCloseFence(p.stack, false)
				want = tcp.StateFinWait2
			}
			b := &finalACKBarrier{port: p.port, ack: p.seq + 1, entered: make(chan struct{}), release: make(chan struct{})}
			unblock := sync.OnceFunc(func() { close(b.release) })
			defer unblock()
			link.barrier.Store(b)
			p.inject(p.packet(p.seq, p.ack, header.TCPFlagFin|header.TCPFlagAck, nil))
			closeSignal(t, b.entered, "FIN ACK without hooks")
			if state := tcp.EndpointState(ep.State()); state != want {
				t.Errorf("hook-free FIN changed state before ACK: got %s want upstream %s", state, want)
			}
		})
	}
}

func (p *peer) windowACK(window uint16) []byte {
	b := p.packet(p.seq, p.ack, header.TCPFlagAck, nil)
	ip := header.IPv4(b)
	h := header.TCP(b[ip.HeaderLength():])
	h.SetWindowSize(window)
	h.SetChecksum(0)
	h.SetChecksum(^checksum.Checksum(h, header.PseudoHeaderChecksum(tcp.ProtocolNumber, appAddr, remoteAddr, uint16(len(h)))))
	return b
}

func TestCloseKeepsQueuedDataCounted(t *testing.T) {
	for _, simultaneous := range []bool{false, true} {
		name := "last_ack"
		if simultaneous {
			name = "closing"
		}
		t.Run(name, func(t *testing.T) {
			limits := flows.Defaults()
			limits.Flows = 1
			p := newPeerOptions(t, false, limits, ns.DefaultOptions())
			p.open(1000)
			p.upload([]byte("up"))
			ep := p.endpoint()
			p.inject(p.windowACK(0))
			// An invalid reset forces processing of the preceding window ACK,
			// but must not retire this still-live flow (RFC 5961).
			p.inject(p.packet(p.seq+1, p.ack, header.TCPFlagRst|header.TCPFlagAck, nil))
			if g := p.table.Stats(); g.Flows != 1 {
				t.Fatal("invalid reset freed a live flow", g)
			}
			if !simultaneous {
				p.inject(p.packet(p.seq, p.ack, header.TCPFlagFin|header.TCPFlagAck, nil))
				p.seq++
				p.receiveEOF()
				if g := p.table.Stats(); g.Flows != 1 {
					t.Fatal("half-close freed a live flow", g)
				}
			}
			payload := bytes.NewReader([]byte("still queued"))
			if n, err := ep.Write(payload, tcpip.WriteOptions{}); err != nil || n != 12 {
				t.Fatal("queue payload", n, err)
			}
			if err := ep.Shutdown(tcpip.ShutdownWrite); err != nil {
				t.Fatal(err)
			}
			if simultaneous {
				p.inject(p.packet(p.seq, p.ack, header.TCPFlagFin|header.TCPFlagAck, nil))
				p.seq++
				for p.wait(header.TCPFlagAck).AckNumber() != p.seq {
				}
			}
			want := tcp.StateLastAck
			if simultaneous {
				want = tcp.StateClosing
			}
			if state := tcp.EndpointState(ep.State()); state != want {
				t.Fatalf("state=%s want=%s", state, want)
			}
			if _, tx := ep.BufferUsage(); tx < 12 {
				t.Fatal("test did not retain queued data", tx)
			}
			if g := p.table.Stats(); g.Flows != 1 {
				t.Fatal("queued payload under-counted", g)
			}
			p.inject(p.windowACK(65535))
			var got []byte
			for {
				h := p.wait(header.TCPFlagAck)
				data := h[h.DataOffset():]
				got = append(got, data...)
				if len(data) != 0 {
					p.ack = h.SequenceNumber() + uint32(len(data))
				}
				if h.Flags().Contains(header.TCPFlagFin) {
					p.ack = h.SequenceNumber() + 1
					break
				}
			}
			if string(got) != "still queued" {
				t.Fatalf("queued payload = %q", got)
			}
			if g := p.table.Stats(); g.Flows != 1 {
				t.Fatal("unacknowledged data under-counted", g)
			}
			p.stack.Pause()
			defer p.stack.Resume()
			// Acknowledge all payload but deliberately leave FIN unacknowledged.
			// Capacity becomes reusable here, not at FIN emission while data
			// was still retransmittable, and not only after the last FIN ACK.
			p.inject(p.packet(p.seq, p.ack-1, header.TCPFlagAck, nil))
			if g := p.table.Stats(); g.Flows != 0 {
				t.Fatal("payload ACK did not retire the FIN-only flow", g)
			}
			p.inject(p.packet(p.seq, p.ack, header.TCPFlagAck, nil))
			if g := p.table.Stats(); g.Flows != 0 {
				t.Fatal("final ACK did not retire", g)
			}
		})
	}
}

func TestCloseRSTDuringHandshake(t *testing.T) {
	limits := flows.Defaults()
	limits.Flows = 1
	p := newPeerOptions(t, false, limits, ns.DefaultOptions())
	releaseCleanup := p.holdRelayCleanup()
	defer releaseCleanup()
	p.seq = 1000
	p.inject(p.packet(p.seq, 0, header.TCPFlagSyn, nil))
	h := p.wait(header.TCPFlagSyn | header.TCPFlagAck)
	p.ack, p.seq = h.SequenceNumber()+1, p.seq+1
	p.stack.Pause()
	resume := sync.OnceFunc(p.stack.Resume)
	defer resume()
	p.inject(p.packet(p.seq, p.ack, header.TCPFlagAck, nil))
	p.inject(p.packet(p.seq, p.ack, header.TCPFlagRst|header.TCPFlagAck, nil))
	if g := p.table.Stats(); g.Flows != 0 {
		t.Error("reset during setup retained admission", g)
	}
	old := <-p.accepted
	defer old.conn.Close()
	p.port++
	p.openWith(500, func(syn []byte) { p.inject(syn); resume() })
	releaseCleanup()
	p.upload([]byte("replacement"))
	p.closeActive()
	if p.table.Stats().Rejected != 0 || p.stack.Stats().TCP.ResetsSent.Value() != 0 {
		t.Fatal(p.diagnostics())
	}
}

func TestCloseBeforeFinalACK(t *testing.T) {
	for _, simultaneous := range []bool{false, true} {
		name := "last_ack"
		if simultaneous {
			name = "closing"
		}
		t.Run(name, func(t *testing.T) {
			limits := flows.Defaults()
			limits.Flows = 1
			p := newPeerOptions(t, false, limits, ns.DefaultOptions())
			p.open(1000)
			p.upload([]byte("old"))
			releaseCleanup := p.holdRelayCleanup()
			defer releaseCleanup()
			p.prepareFinalACK(simultaneous) // Lose the final ACK entirely.
			if g := p.table.Stats(); g.Flows != 0 {
				t.Error("a lost final ACK retained a payload-free flow", p.diagnostics())
			}
			p.port++
			p.open(500)
			releaseCleanup()
			p.upload([]byte("replacement"))
			p.closeActive()
			if g := p.table.Stats(); g.Rejected != 0 || g.Admitted != 2 {
				t.Fatal(p.diagnostics())
			}
		})
	}
}
