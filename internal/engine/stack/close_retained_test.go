package stack_test

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
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
			// Fill the retained cap with the first endpoint. The second resets
			// after its FIN so losing that FIN cannot leave the app waiting.
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
			if state := tcp.EndpointState(second.State()); state != tcp.StateError {
				t.Fatal("overflow endpoint can keep retransmitting", state)
			}
			if g := p.table.Stats(); g.TimeWait != 1 || g.TimeWaitSkipped != 1 || g.Flows != 0 {
				t.Fatal("retained cap or live count wrong", g)
			}
			readCloseReset(t, p)
			// Unknown ACKs get the upstream reset, including a harmless late
			// final ACK from an app whose FIN-only endpoint hit the cap.
			p.inject(p.packet(p.seq, p.ack, header.TCPFlagAck, nil))
			if h := readCloseReset(t, p); h.SequenceNumber() != p.ack {
				t.Fatal("late ACK reset has the wrong sequence")
			}
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
			if p.stack.Stats().TCP.ResetsSent.Value() != 2 || p.table.Stats().Rejected != 0 {
				t.Fatal(p.diagnostics())
			}
		})
	}
}

func readCloseReset(t testing.TB, p *peer) header.TCP {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		h := p.read(time.Until(deadline))
		if h == nil {
			break
		}
		if h.Flags().Contains(header.TCPFlagRst) {
			return h
		}
	}
	t.Fatal("missing TCP reset", p.diagnostics())
	return nil
}

type dropCloseFINLink struct {
	*ns.Link
	drop    atomic.Bool
	dropped atomic.Int32
	finSeq  atomic.Uint32
}

func (l *dropCloseFINLink) WritePackets(pkts gv.PacketBufferList) (int, tcpip.Error) {
	for _, pkt := range pkts.AsSlice() {
		h := header.TCP(pkt.TransportHeader().Slice())
		if l.drop.Load() && h.Flags().Contains(header.TCPFlagFin) {
			l.finSeq.Store(h.SequenceNumber())
			l.dropped.Add(1)
			continue
		}
		var one gv.PacketBufferList
		one.PushBack(pkt)
		l.Link.WritePackets(one)
	}
	return pkts.Len(), nil
}

func TestCloseRetainedCapLostFIN(t *testing.T) {
	limits := flows.Defaults()
	limits.Flows, limits.PerApp, limits.TimeWait = 1, 1, 1
	link := &dropCloseFINLink{Link: ns.NewLink()}
	p := newPeerLink(t, false, limits, ns.DefaultOptions(), link.Link, link)
	p.open(1000)
	p.upload([]byte("retained"))
	p.prepareFinalACK(false)
	if g := p.table.Stats(); g.Flows != 0 || g.TimeWait != 1 {
		t.Fatal("retained cap not occupied", g)
	}
	p.port++
	p.open(2000)
	p.upload([]byte("half-close then wait for EOF"))
	p.inject(p.packet(p.seq, p.ack, header.TCPFlagFin|header.TCPFlagAck, nil))
	p.seq++
	p.receiveEOF()
	link.drop.Store(true)
	p.current.conn.CloseWrite()
	closeSignal(t, p.current.sentEOF, "overflow CloseWrite with dropped FIN")
	if link.dropped.Load() != 1 || link.finSeq.Load() != p.ack {
		t.Fatal("test did not drop the only FIN before EOF", link.dropped.Load(), link.finSeq.Load(), p.ack)
	}
	// gVisor's active reset uses SND.NXT, which includes the lost FIN. An
	// RFC 5961 peer challenges this in-window reset instead of accepting it.
	if h := readCloseReset(t, p); h.SequenceNumber() != p.ack+1 {
		t.Fatal("overflow reset did not follow the lost FIN")
	}
	p.inject(p.packet(p.seq, p.ack, header.TCPFlagAck, nil))
	if h := readCloseReset(t, p); h.SequenceNumber() != p.ack || h.Flags() != header.TCPFlagRst {
		t.Fatal("challenge ACK did not get an acceptable reset")
	}
	if g := p.table.Stats(); g.Flows != 0 || g.TimeWait != 1 || g.TimeWaitSkipped != 1 || g.Rejected != 0 {
		t.Fatal("overflow accounting", g)
	}
	t.Log("dropped the overflow FIN; active reset plus challenge ACK ends the half-closed peer without waiting for EOF")
}

func TestCloseUnknownACKGetsReset(t *testing.T) {
	p := newPeer(t, false)
	p.inject(p.packet(1000, 4000, header.TCPFlagAck, nil))
	if h := readCloseReset(t, p); h.SequenceNumber() != 4000 || h.Flags() != header.TCPFlagRst {
		t.Fatal("unknown keepalive ACK lost the upstream reset")
	}
	if p.dials.Load() != 0 || p.table.Stats().Rejected != 0 {
		t.Fatal("unknown ACK entered admission", p.diagnostics())
	}
}

func TestCloseFenceWakesRemainingSegments(t *testing.T) {
	o := ns.DefaultOptions()
	o.Clock = faketime.NewManualClock() // Timers must not supply the missing wakeup either.
	p := newPeerOptions(t, false, flows.Defaults(), o)
	// Keep the relay from starting: any gonet Read/CloseRead/Close would call
	// UnlockUser and could accidentally supply the missing processor wakeup.
	setup := make(chan struct{})
	releaseSetup := sync.OnceFunc(func() { close(setup) })
	defer releaseSetup()
	p.setupGate, p.setupEntered = setup, make(chan struct{}, 1)
	p.open(1000)
	defer p.current.conn.Close()
	closeSignal(t, p.setupEntered, "relay held before setup")
	ep := p.endpoint()
	if err := ep.Shutdown(tcpip.ShutdownWrite); err != nil {
		t.Fatal(err)
	}
	h := p.wait(header.TCPFlagFin)
	p.ack = h.SequenceNumber() + 1
	p.stack.Pause()
	resume := sync.OnceFunc(p.stack.Resume)
	defer resume()
	drain := tcp.SetLocalCloseFence(p.stack, true)
	fin := p.packet(p.seq, p.ack, header.TCPFlagFin|header.TCPFlagAck, nil)
	for range 2 {
		pkt := gv.NewPacketBuffer(gv.PacketBufferOptions{Payload: buffer.MakeWithData(fin)})
		pkt.NetworkHeader().Consume(header.IPv4MinimumSize)
		pkt.TransportHeader().Consume(header.TCPMinimumSize)
		pkt.NetworkProtocolNumber, pkt.NICID = header.IPv4ProtocolNumber, ns.NIC
		p.stack.TransportProtocolInstance(tcp.ProtocolNumber).(interface {
			QueuePacket(gv.TransportEndpoint, gv.TransportEndpointID, *gv.PacketBuffer)
		}).QueuePacket(ep, ep.TransportEndpointInfo.ID, pkt)
		pkt.DecRef()
	}
	if got := drain(); got != ep || tcp.EndpointState(ep.State()) != tcp.StateTimeWait {
		t.Fatal("fence did not enter TIME_WAIT")
	}
	p.seq++
	if h := p.wait(header.TCPFlagAck); h.AckNumber() != p.seq {
		t.Fatal("first FIN was not acknowledged")
	}
	// TIME_WAIT is outside the fence's work. There must still be a worker
	// wakeup for the second marked FIN, with no more ingress to trigger it.
	resume()
	if h := p.wait(header.TCPFlagAck); h.AckNumber() != p.seq {
		t.Fatal("queued FIN retransmission was stranded after the fence")
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
				if g := p.table.Stats(); g.Handshakes != cap-1 {
					t.Fatal("reset retained its handshake admission", g)
				}
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

func TestCloseHandshakeCompletionOwnsRelease(t *testing.T) {
	limits := flows.Defaults()
	limits.Flows, limits.Handshakes = 1, 1
	p := newPeerOptions(t, false, limits, ns.DefaultOptions())
	release := p.holdRelayCleanup()
	defer release()
	// Force open to finish first: process the validated RST, but omit the
	// forwarder's after-ingress accounting. Once pending is removed, open
	// must own retirement; a later fence no longer has a ticket to find.
	drain := tcp.SetLocalCloseFence(p.stack, true)
	p.link.SetAfterInbound(func() { drain() })
	p.seq = 1000
	p.inject(p.packet(p.seq, 0, header.TCPFlagSyn, nil))
	h := p.wait(header.TCPFlagSyn | header.TCPFlagAck)
	p.seq++
	p.ack = h.SequenceNumber() + 1
	old := <-p.accepted
	defer old.conn.Close()
	if g := p.table.Stats(); g.Flows != 1 || g.Handshakes != 1 {
		t.Fatal("handshake must occupy its slot before the reset", g)
	}
	p.inject(p.packet(p.seq, p.ack, header.TCPFlagRst|header.TCPFlagAck, nil))
	closeSignal(t, old.closeEntered, "failed handshake completed before deferred remote close")
	if g := p.table.Stats(); g.Flows != 0 || g.Handshakes != 0 {
		t.Fatal("completed handshake retained admission behind remote cleanup", g)
	}
	p.port++
	p.open(2000)
	release()
	p.upload([]byte("replacement"))
	if p.table.Stats().Rejected != 0 || p.stack.Stats().TCP.ResetsSent.Value() != 0 {
		t.Fatal(p.diagnostics())
	}
}

func TestCloseHandshakeBeforeHangupNotification(t *testing.T) {
	for _, stage := range []string{"handshake", "setup"} {
		t.Run(stage, func(t *testing.T) {
			limits := flows.Defaults()
			limits.Flows, limits.Handshakes = 1, 1
			p := newPeerOptions(t, false, limits, ns.DefaultOptions())
			releaseRemote := p.holdRelayCleanup()
			defer releaseRemote()
			setup := make(chan struct{})
			releaseSetup := sync.OnceFunc(func() { close(setup) })
			defer releaseSetup()
			p.setupGate, p.setupEntered = setup, make(chan struct{}, 1)
			p.seq = 1000
			p.inject(p.packet(p.seq, 0, header.TCPFlagSyn, nil))
			synACK := p.wait(header.TCPFlagSyn | header.TCPFlagAck)
			p.seq++
			p.ack = synACK.SequenceNumber() + 1
			p.current = <-p.accepted
			defer p.current.conn.Close()
			if stage == "setup" {
				p.inject(p.packet(p.seq, p.ack, header.TCPFlagAck, nil))
				closeSignal(t, p.setupEntered, "pending endpoint setup")
			}
			ep := p.endpoint()
			if g := p.table.Stats(); g.Flows != 1 || g.Handshakes != 1 {
				t.Fatal("handshake must occupy its slot before closing", g)
			}
			entered, resume := make(chan struct{}), make(chan struct{})
			release := sync.OnceFunc(func() { close(resume) })
			defer release()
			// The queued SYN is only a barrier: this callback runs after the old
			// processor publishes ERROR and unlocks, but before its waiter notification.
			tcp.SetTimeWaitHandler(p.stack, func(gv.TransportEndpointID, *gv.PacketBuffer) bool {
				close(entered)
				<-resume
				return true
			})
			ep.LockUser()
			queue := func(raw []byte) {
				pkt := gv.NewPacketBuffer(gv.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
				defer pkt.DecRef()
				pkt.NetworkHeader().Consume(header.IPv4MinimumSize)
				pkt.TransportHeader().Consume(header.TCPMinimumSize)
				pkt.NetworkProtocolNumber, pkt.NICID = header.IPv4ProtocolNumber, ns.NIC
				p.stack.TransportProtocolInstance(tcp.ProtocolNumber).(interface {
					QueuePacket(gv.TransportEndpoint, gv.TransportEndpointID, *gv.PacketBuffer)
				}).QueuePacket(ep, ep.TransportEndpointInfo.ID, pkt)
			}
			queue(p.packet(p.seq, p.ack, header.TCPFlagRst|header.TCPFlagAck, nil))
			queue(p.packet(500, 0, header.TCPFlagSyn, nil))
			ep.UnlockUser()
			closeSignal(t, entered, "processor paused before hangup notification")
			if state := tcp.EndpointState(ep.State()); state != tcp.StateError {
				t.Fatal("barrier did not follow endpoint removal", state)
			}
			// Run the normal after-ingress fence on that already-closed endpoint.
			// This extra RST to the unregistered tuple is ignored by normal TCP.
			p.inject(p.packet(p.seq, p.ack, header.TCPFlagRst|header.TCPFlagAck, nil))
			if g := p.table.Stats(); g.Flows != 0 || g.Handshakes != 0 {
				t.Fatal("close fence retained admission until a delayed notification", g)
			}
			p.port++
			p.open(2000)
			release()
			releaseSetup()
			releaseRemote()
			p.upload([]byte("replacement"))
			if g := p.table.Stats(); g.Flows != 1 || g.Rejected != 0 || p.stack.Stats().TCP.ResetsSent.Value() != 0 {
				t.Fatal("replacement was rejected or under-counted", p.diagnostics())
			}
			p.closeActive()
		})
	}
}

func TestCloseFencePreservesListenerProcessing(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			p := newPeer(t, false)
			tcp.SetLocalCloseFence(p.stack, enabled)
			var wq waiter.Queue
			ep, err := p.stack.NewEndpoint(tcp.ProtocolNumber, header.IPv4ProtocolNumber, &wq)
			if err != nil {
				t.Fatal(err)
			}
			defer ep.Close()
			if err := ep.Bind(tcpip.FullAddress{Port: 443}); err != nil {
				t.Fatal(err)
			}
			if err := ep.Listen(1); err != nil {
				t.Fatal(err)
			}
			p.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, func(gv.TransportEndpointID, *gv.PacketBuffer) bool {
				t.Error("packet bypassed the listener")
				return true
			})
			p.stack.Pause()
			// LISTEN rejects an unexpected ACK with a reset. FIN must not
			// divert it to a fence which only processes connecting/live flows.
			p.inject(p.packet(1000, 500, header.TCPFlagFin|header.TCPFlagAck, nil))
			p.stack.Resume()
			if h := p.read(time.Second); h == nil || !h.Flags().Contains(header.TCPFlagRst) {
				t.Fatal("listener lost its normal invalid-ACK response")
			}
		})
	}
}
