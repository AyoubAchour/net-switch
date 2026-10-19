package stack_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func TestCloseRetainedCap(t *testing.T) {
	for _, simultaneous := range []bool{false, true} {
		t.Run(fmt.Sprintf("simultaneous_%t", simultaneous), func(t *testing.T) {
			limits := flows.Defaults()
			limits.Flows, limits.PerApp, limits.TimeWait = 1, 1, 1
			p := newPeerOptions(t, false, limits, ns.DefaultOptions())
			p.open(1000)
			p.upload([]byte("first"))
			firstACK := p.prepareFinalACK(simultaneous)
			first := p.endpoint()
			if g := p.table.Stats(); g.Flows != 0 || g.TimeWait != 1 {
				t.Fatal("lost final ACK is not retained", g)
			}
			p.port++
			p.open(2000)
			p.upload([]byte("second"))
			second := p.endpoint()
			// Fill the same retained cap with the first endpoint. The second
			// must close silently after its FIN, even if no final ACK ever comes.
			if simultaneous {
				p.current.conn.CloseWrite()
				h := p.wait(header.TCPFlagFin)
				p.inject(p.packet(p.seq, p.ack, header.TCPFlagFin|header.TCPFlagAck, nil))
				p.seq++
				p.ack = h.SequenceNumber() + 1
			} else {
				p.inject(p.packet(p.seq, p.ack, header.TCPFlagFin|header.TCPFlagAck, nil))
				p.seq++
				p.receiveEOF()
				p.current.conn.CloseWrite()
				h := p.wait(header.TCPFlagFin)
				p.ack = h.SequenceNumber() + 1
			}
			closeSignal(t, p.current.sentEOF, "retained overflow CloseWrite")
			if state := tcp.EndpointState(second.State()); state != tcp.StateClose {
				t.Fatal("overflow endpoint can keep retransmitting", state)
			}
			if g := p.table.Stats(); g.TimeWait != 1 || g.TimeWaitSkipped != 1 || g.Flows != 0 {
				t.Fatal("retained cap or live count wrong", g)
			}
			// A delayed final ACK to the silently removed endpoint stays silent.
			p.inject(p.packet(p.seq, p.ack, header.TCPFlagAck, nil))
			p.inject(firstACK)
			if simultaneous {
				if state := tcp.EndpointState(first.State()); state != tcp.StateTimeWait {
					t.Fatal("CLOSING did not transfer its retained slot to TIME_WAIT", state)
				}
				if g := p.table.Stats(); g.TimeWait != 1 || g.TimeWaitSkipped != 1 {
					t.Fatal("transition reserved twice", g)
				}
			} else if g := p.table.Stats(); g.TimeWait != 0 {
				t.Fatal("LAST_ACK removal leaked retained slot", g)
			}
			if p.stack.Stats().TCP.ResetsSent.Value() != 0 || p.table.Stats().Rejected != 0 {
				t.Fatal(p.diagnostics())
			}
		})
	}
}

func TestCloseHandshakeCap(t *testing.T) {
	for _, cap := range []int{1, 2048} {
		t.Run(fmt.Sprint(cap), func(t *testing.T) {
			if testing.Short() && cap == 2048 {
				t.Skip("full handshake cap runs in CI")
			}
			limits := flows.Defaults()
			limits.Handshakes = cap
			p := newPeerOptions(t, false, limits, ns.DefaultOptions())
			release := p.holdRelayCleanup()
			defer release()
			gate := make(chan struct{})
			unblock := sync.OnceFunc(func() { close(gate) })
			defer unblock()
			p.setupGate, p.setupEntered = gate, make(chan struct{}, 1)
			start := func() {
				p.seq = 1000
				p.inject(p.packet(p.seq, 0, header.TCPFlagSyn, nil))
				h := p.wait(header.TCPFlagSyn | header.TCPFlagAck)
				p.seq++
				p.ack = h.SequenceNumber() + 1
				p.inject(p.packet(p.seq, p.ack, header.TCPFlagAck, nil))
				closeSignal(t, p.setupEntered, "open held before handshake completion")
				remote := <-p.accepted
				p.current = remote
				deferClose := remote.conn
				t.Cleanup(func() { deferClose.Close() })
			}
			for range cap {
				p.port++
				start()
			}
			for range 3 {
				if g := p.table.Stats(); g.Handshakes != cap {
					t.Fatal("handshake cap not filled", g)
				}
				p.inject(p.packet(p.seq, p.ack, header.TCPFlagRst|header.TCPFlagAck, nil))
				if cap != 1 {
					p.port++
				}
				start()
			}
			unblock()
			release()
			p.upload([]byte("replacement survived old setup"))
			if p.table.Stats().Rejected != 0 || p.stack.Stats().TCP.ResetsSent.Value() != 0 || p.stack.Stats().TCP.ForwardMaxInFlightDrop.Value() != 0 {
				t.Fatal("handshake gate retained a reset request", p.diagnostics())
			}
			t.Logf("%d pending handshakes; 3 reset/replacements while open is blocked before completion; no rejection or upstream drop", cap)
		})
	}
}
