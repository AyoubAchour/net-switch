package stack_test

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func TestTimeWaitImmediateReuse(t *testing.T) {
	for _, relation := range []string{"below", "equal", "above"} {
		t.Run(relation, func(t *testing.T) {
			p := newPeer(t, false)
			p.open(1000)
			p.upload([]byte("initial"))
			p.closeActive()
			var slowest time.Duration
			for i := range 1000 {
				seq := p.seq
				if relation == "below" {
					seq -= 100
				}
				if relation == "above" {
					seq += 100
				}
				slowest = max(slowest, p.open(seq))
				p.upload([]byte(fmt.Sprintf("reuse %d", i)))
				p.closeActive()
			}
			t.Logf("1000 immediate reuses, no timestamps, ISN %s old RcvNxt; slowest %s; dials=%d admitted=%d; every payload SHA-256 checked", relation, slowest, p.dials.Load(), p.table.Stats().Admitted)
			if slowest > 100*time.Millisecond || p.dials.Load() != 1001 || p.table.Stats().Admitted != 1001 {
				t.Fatal("reuse, dial or admission gate failed")
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
			if d := p.open(1000); d > 100*time.Millisecond {
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
	for i := range 1000 {
		if d := p.open(p.seq - 100); d > 100*time.Millisecond {
			t.Fatalf("reuse %d took %s", i, d)
		}
		p.upload(bytes.Repeat([]byte{byte(i)}, 100))
		p.closeActive()
	}
	if p.dials.Load() != 1001 {
		t.Fatal("extra or missing dial")
	}
	t.Log("1000 no-timestamp reuses across sequence wrap; all payload hashes match")
}

func TestTimeWaitAfter100MB(t *testing.T) {
	if testing.Short() {
		t.Skip("100 MB gate runs in CI")
	}
	p := newPeer(t, false)
	p.open(1000)
	block := bytes.Repeat([]byte{1, 2, 3, 4}, 2048)
	for left := 100_000_000; left > 0; {
		n := min(left, len(block))
		p.upload(block[:n])
		left -= n
	}
	p.closeActive()
	for i := range 1000 {
		seq := p.seq + uint32(i%3)*100 - 100
		if d := p.open(seq); d > 100*time.Millisecond {
			t.Fatalf("reuse %d took %s", i, d)
		}
		p.upload([]byte(fmt.Sprintf("after 100 MB: %d", i)))
		p.closeActive()
	}
	if p.dials.Load() != 1001 {
		t.Fatal("extra or missing dial")
	}
	t.Log("100 MB + 1000 immediate reuses below/equal/above RcvNxt without timestamps; all SHA-256 hashes match")
}

func TestTimeWaitOldSegmentsBeforeNewSYN(t *testing.T) {
	p := newPeer(t, false)
	p.open(1000)
	old := p.upload([]byte("stale payload"))
	// A retransmitted SYN precedes the old connection's FIN in the ordered
	// local TUN stream. Deliver it while that incarnation still owns the tuple.
	p.inject(p.syn)
	fin := p.closeActive()
	p.inject(old)
	p.inject(fin)
	p.inject(p.packet(p.seq, p.ack, header.TCPFlagRst|header.TCPFlagAck, nil))
	if d := p.open(p.seq - 100); d > 100*time.Millisecond {
		t.Fatal(d)
	}
	p.upload([]byte("fresh payload"))
	p.closeActive()
	if p.dials.Load() != 2 || p.table.Stats().Admitted != 2 {
		t.Fatal("old segments created a flow")
	}
}

func TestTimeWaitLostFinalACK(t *testing.T) {
	clock := faketime.NewManualClock()
	o := ns.DefaultOptions()
	o.Clock = clock
	if o.TimeWait != 60*time.Second {
		t.Fatal("lost-ACK protection changed")
	}
	p := newPeerOptions(t, false, flows.Defaults(), o)
	p.open(1000)
	p.upload([]byte("before lost ACK"))
	fin := p.closeActive()
	// The app lost the final ACK and retransmits near expiry. That ACK resets
	// TIME_WAIT, so it is still protected at 60 seconds from the initial FIN.
	id := gv.TransportEndpointID{LocalAddress: remoteAddr, LocalPort: 443, RemoteAddress: appAddr, RemotePort: p.port}
	ep, ok := p.stack.FindTransportEndpoint(header.IPv4ProtocolNumber, tcp.ProtocolNumber, id, ns.NIC).(*tcp.Endpoint)
	if !ok {
		t.Fatal("TIME_WAIT endpoint disappeared before its deadline")
	}
	for _, advance := range []time.Duration{59 * time.Second, time.Second} {
		// The ACK reaches the link before handleTimeWait refreshes its timer.
		// Finish that critical section before jumping the simulated clock;
		// otherwise the artificial jump can expire the old timer mid-packet.
		// This is only a clock barrier: no reuse test waits for endpoint removal.
		ep.LockUser()
		state := tcp.EndpointState(ep.State())
		ep.UnlockUser()
		if state != tcp.StateTimeWait {
			t.Fatalf("before advancing %s: endpoint state %s", advance, state)
		}
		clock.Advance(advance)
		p.inject(fin)
		h := p.wait(header.TCPFlagAck)
		if h.Flags().Contains(header.TCPFlagRst) || h.AckNumber() != p.seq {
			t.Fatal("lost FIN ACK was reset")
		}
	}
	if p.dials.Load() != 1 {
		t.Fatal("FIN retransmission dialed")
	}
	t.Log("FIN retransmits at 59 s and 60 s receive ACK, never RST")
}

func TestTimeWaitBlockedAndBudgetReuse(t *testing.T) {
	limits := flows.Defaults()
	limits.Flows = 1
	limits.TimeWait = 1
	p := newPeerOptions(t, false, limits, ns.DefaultOptions())
	p.open(1000)
	p.upload([]byte("first"))
	p.closeActive()
	// Releasing the old endpoint before Begin lets its own tuple reuse the
	// last slot. A different tuple still receives an immediate budget RST.
	p.port++
	p.inject(p.packet(500, 0, header.TCPFlagSyn, []byte("syn data")))
	h := p.read(time.Second)
	if h == nil || !h.Flags().Contains(header.TCPFlagRst) || h.AckNumber() != 509 {
		t.Fatal("budget SYN/data reset missing")
	}
	p.port--
	p.open(1000)
	p.upload([]byte("second"))
	p.closeActive()
	p.config.Blocked = []string{"B"}
	if _, err := p.table.Apply(policy.Revision{N: 2, Hash: policy.Hash(p.config), Config: p.config}); err != nil {
		t.Fatal(err)
	}
	p.inject(p.packet(1000, 0, header.TCPFlagSyn, nil))
	h = p.read(time.Second)
	if h == nil || !h.Flags().Contains(header.TCPFlagRst) {
		t.Fatal("blocked reuse did not reset")
	}
	if p.dials.Load() != 2 || p.table.Stats().Admitted != 2 {
		t.Fatal("rejected SYN advanced k or dialed")
	}
}

func TestTimeWaitThreeQueuedSYNsDialOnce(t *testing.T) {
	p := newPeer(t, false)
	p.open(1000)
	p.upload([]byte("old"))
	p.closeActive()
	id := gv.TransportEndpointID{LocalAddress: remoteAddr, LocalPort: 443, RemoteAddress: appAddr, RemotePort: p.port}
	ep, ok := p.stack.FindTransportEndpoint(header.IPv4ProtocolNumber, tcp.ProtocolNumber, id, ns.NIC).(*tcp.Endpoint)
	if !ok {
		t.Fatal("old endpoint already removed")
	}
	if d := p.openWith(1000, func(syn []byte) {
		ep.LockUser()
		defer ep.UnlockUser()
		for range 3 {
			p.inject(syn)
		}
	}); d > 100*time.Millisecond {
		t.Fatal(d)
	}
	p.upload([]byte("three SYNs, one payload"))
	p.closeActive()
	if p.dials.Load() != 2 || p.table.Stats().Admitted != 2 {
		t.Fatal("queued duplicates dialed or advanced k")
	}
	if h := p.read(5 * time.Millisecond); h != nil && h.Flags().Contains(header.TCPFlagRst) {
		t.Fatal("queued SYN was reset")
	}
	t.Log("three SYNs queued on TIME_WAIT: one replacement dial, one k advance, no RST")
}

func TestTimeWaitSYNBetweenRemovalAndHook(t *testing.T) {
	limits := flows.Defaults()
	limits.Flows, limits.TimeWait = 1, 1
	p := newPeerOptions(t, false, limits, ns.DefaultOptions())
	p.open(1000)
	p.upload([]byte("old"))
	p.closeActive()
	entered, release := make(chan struct{}), make(chan struct{})
	// Stop exactly after the old endpoint is unregistered, before its
	// callback reaches admission. The next TUN SYN now reaches Handle directly.
	tcp.SetTimeWaitHandler(p.stack, func(id gv.TransportEndpointID, pkt *gv.PacketBuffer) bool {
		close(entered)
		<-release
		return p.forward.Handle(id, pkt)
	})
	if d := p.openWith(1000, func(syn []byte) {
		p.inject(syn)
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("reopen hook not reached")
		}
		p.inject(syn)
		close(release)
	}); d > 100*time.Millisecond {
		t.Fatal(d)
	}
	p.upload([]byte("replacement"))
	p.closeActive()
	if p.dials.Load() != 2 || p.table.Stats().Admitted != 2 {
		t.Fatal("retirement gap duplicated admission")
	}
}

func TestTimeWaitLateHookDoesNotReadmitLiveFlow(t *testing.T) {
	limits := flows.Defaults()
	limits.Flows, limits.TimeWait = 1, 1
	p := newPeerOptions(t, false, limits, ns.DefaultOptions())
	p.open(1000)
	p.upload([]byte("old"))
	p.closeActive()
	type retained struct {
		id     gv.TransportEndpointID
		packet *gv.PacketBuffer
	}
	hook := make(chan retained, 1)
	tcp.SetTimeWaitHandler(p.stack, func(id gv.TransportEndpointID, pkt *gv.PacketBuffer) bool {
		pkt.IncRef()
		hook <- retained{id, pkt}
		return true
	})
	var delayed retained
	p.openWith(1000, func(syn []byte) {
		p.inject(syn)
		select {
		case delayed = <-hook:
		case <-time.After(time.Second):
			t.Fatal("reopen hook not reached")
		}
		p.inject(syn)
	})
	defer delayed.packet.DecRef()
	p.upload([]byte("already established"))
	p.forward.Handle(delayed.id, delayed.packet)
	if g := p.table.Stats(); g.Rejected != 0 || g.Admitted != 2 {
		t.Fatal("late SYN callback readmitted or reset a live flow", g)
	}
	p.upload([]byte("still clean"))
	p.closeActive()
	if p.dials.Load() != 2 {
		t.Fatal("late callback dialed again")
	}
}

func TestTimeWaitSimultaneousCloseReuse(t *testing.T) {
	p := newPeer(t, false)
	p.open(1000)
	p.upload([]byte("before simultaneous FIN"))
	p.current.conn.CloseWrite()
	h := p.wait(header.TCPFlagFin)
	// Our FIN is still unacknowledged when the app's FIN arrives.
	p.inject(p.packet(p.seq, p.ack, header.TCPFlagFin|header.TCPFlagAck, nil))
	p.seq++
	p.ack = h.SequenceNumber() + 1
	p.wait(header.TCPFlagAck)
	p.inject(p.packet(p.seq, p.ack, header.TCPFlagAck, nil))
	p.current.conn.Close()
	if d := p.open(1000); d > 100*time.Millisecond {
		t.Fatal(d)
	}
	p.upload([]byte("after simultaneous FIN"))
	p.closeActive()
	if p.dials.Load() != 2 {
		t.Fatal("unexpected dials")
	}
}

func TestTimeWaitThousandPerSecondCap(t *testing.T) {
	limits := flows.Defaults()
	limits.TimeWait = 64
	p := newPeerOptions(t, false, limits, ns.DefaultOptions())
	start := time.Now()
	for i := range 1000 {
		p.port = uint16(40000 + i)
		if i < limits.TimeWait {
			p.open(1000)
			p.upload([]byte("cap"))
			p.closeActive()
		} else {
			p.inject(p.packet(1000, 0, header.TCPFlagSyn, nil))
			if h := p.read(time.Second); h == nil || !h.Flags().Contains(header.TCPFlagRst) {
				t.Fatal("cap did not reject")
			}
		}
		if g := p.table.Stats(); g.Flows > limits.TimeWait || g.TimeWait > limits.TimeWait {
			t.Fatal(g)
		}
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("offered less than 1000 connections/s: %s", d)
	} else {
		t.Logf("1000 attempts in %s; retained endpoints <= %d", d, limits.TimeWait)
	}
	// The shared monitor counts retained endpoints, without evicting any.
	deadline := time.Now().Add(time.Second)
	for p.table.Stats().TimeWait != limits.TimeWait && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if g := p.table.Stats(); g.TimeWait != limits.TimeWait || g.Flows != limits.TimeWait {
		t.Fatal(g)
	}
}
