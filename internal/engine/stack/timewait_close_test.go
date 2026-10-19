package stack_test

import (
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
)

type cleanupClock struct {
	*faketime.ManualClock
	entered, release chan struct{}
	once             sync.Once
	mu               sync.Mutex
	latest           *cleanupTimer
	target           atomic.Pointer[cleanupTimer]
}

func (c *cleanupClock) AfterFunc(d time.Duration, f func()) tcpip.Timer {
	timer := c.ManualClock.AfterFunc(d, f)
	if d == 60*time.Second {
		wrapped := &cleanupTimer{Timer: timer, clock: c}
		c.mu.Lock()
		c.latest = wrapped
		c.mu.Unlock()
		return wrapped
	}
	return timer
}

type cleanupTimer struct {
	tcpip.Timer
	clock *cleanupClock
}

func (t *cleanupTimer) Stop() bool {
	if t.clock.target.Load() == t {
		t.clock.once.Do(func() { close(t.clock.entered); <-t.clock.release })
	}
	return t.Timer.Stop()
}

func TestTimeWaitSYNBeforeRemoval(t *testing.T) {
	clock := &cleanupClock{ManualClock: faketime.NewManualClock(), entered: make(chan struct{}), release: make(chan struct{})}
	unblock := sync.OnceFunc(func() { close(clock.release) })
	defer unblock()
	o := ns.DefaultOptions()
	o.Clock = clock
	p := newPeerOptions(t, false, flows.Defaults(), o)
	p.open(1000)
	p.upload([]byte("old"))
	p.closeActive()
	id := gv.TransportEndpointID{LocalAddress: remoteAddr, LocalPort: 443, RemoteAddress: appAddr, RemotePort: p.port}
	ep := p.stack.FindTransportEndpoint(header.IPv4ProtocolNumber, tcp.ProtocolNumber, id, ns.NIC).(*tcp.Endpoint)
	ep.LockUser()
	// Under the endpoint lock, the last 60-second timer is now TIME_WAIT's.
	// FIN_WAIT_2 may also have installed a 60-second timer; stopping that
	// older timer during cleanup must not fire this barrier.
	clock.mu.Lock()
	clock.target.Store(clock.latest)
	clock.mu.Unlock()
	state := tcp.EndpointState(ep.State())
	ep.UnlockUser()
	if state != tcp.StateTimeWait || clock.target.Load() == nil {
		t.Fatalf("cannot arm TIME_WAIT cleanup barrier: state=%s", state)
	}
	expired := make(chan struct{})
	go func() { clock.Advance(60 * time.Second); close(expired) }()
	select {
	case <-clock.entered:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not stop its timer")
	}
	if got := p.stack.FindTransportEndpoint(header.IPv4ProtocolNumber, tcp.ProtocolNumber, id, ns.NIC); got != ep {
		t.Fatal("cleanup barrier must precede demux removal")
	}
	p.openWith(1000, func(syn []byte) {
		p.inject(syn) // The old endpoint still owns the tuple at this point.
		unblock()
		<-expired
	})
	p.upload([]byte("replacement"))
	p.closeActive()
	if g := p.table.Stats(); g.Admitted != 2 || g.Rejected != 0 || p.dials.Load() != 2 || p.stack.Stats().TCP.ResetsSent.Value() != 0 {
		t.Fatal("cleanup lost or reset the replacement SYN", g)
	}
}

func TestTimeWaitZeroCapClosingBatch(t *testing.T) {
	limits := flows.Defaults()
	limits.TimeWait = 0
	limits.Flows, limits.PerApp = 1, 1
	p := newPeerOptions(t, false, limits, ns.DefaultOptions())
	p.open(1000)
	p.upload([]byte("old"))
	p.current.conn.CloseWrite()
	h := p.wait(header.TCPFlagFin)
	p.ack = h.SequenceNumber() + 1
	fin := p.packet(p.seq, p.ack, header.TCPFlagFin|header.TCPFlagAck, nil)
	id := gv.TransportEndpointID{LocalAddress: remoteAddr, LocalPort: 443, RemoteAddress: appAddr, RemotePort: p.port}
	ep := p.stack.FindTransportEndpoint(header.IPv4ProtocolNumber, tcp.ProtocolNumber, id, ns.NIC).(*tcp.Endpoint)
	old := p.current
	p.openWith(1000, func(syn []byte) {
		ep.LockUser()
		defer ep.UnlockUser()
		// Queue directly to freeze a whole processor batch. Ordered ingress
		// now finishes a FIN before accepting the next packet.
		queue := func(raw []byte) {
			pkt := gv.NewPacketBuffer(gv.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
			defer pkt.DecRef()
			pkt.NetworkHeader().Consume(header.IPv4MinimumSize)
			pkt.TransportHeader().Consume(header.TCPMinimumSize)
			pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
			p.stack.TransportProtocolInstance(tcp.ProtocolNumber).(interface {
				QueuePacket(gv.TransportEndpoint, gv.TransportEndpointID, *gv.PacketBuffer)
			}).QueuePacket(ep, id, pkt)
		}
		queue(fin)
		for range 3 {
			queue(syn)
		}
	})
	old.conn.Close()
	p.upload([]byte("replacement"))
	if g := p.table.Stats(); g.Flows != 1 {
		t.Fatal("queued close retired the live replacement", p.diagnostics())
	}
	p.closeActive()
	deadline := time.Now().Add(time.Second)
	for p.table.Stats().TimeWaitSkipped != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if g := p.table.Stats(); g.Admitted != 2 || g.Rejected != 0 || g.TimeWait != 0 || g.TimeWaitSkipped != 2 || p.dials.Load() != 2 || p.stack.Stats().TCP.ResetsSent.Value() != 0 {
		t.Fatal("zero-cap batch lost, reset or duplicated the replacement", g)
	}
}

func TestTimeWaitSYNBeforeCloseState(t *testing.T) {
	clock := faketime.NewManualClock()
	o := ns.DefaultOptions()
	o.Clock = clock
	limits := flows.Defaults()
	limits.Flows, limits.PerApp = 1, 1
	p := newPeerOptions(t, false, limits, o)
	p.open(1000)
	p.upload([]byte("old"))
	p.closeActive()
	id := gv.TransportEndpointID{LocalAddress: remoteAddr, LocalPort: 443, RemoteAddress: appAddr, RemotePort: p.port}
	ep := p.stack.FindTransportEndpoint(header.IPv4ProtocolNumber, tcp.ProtocolNumber, id, ns.NIC).(*tcp.Endpoint)
	removed, release, expired := make(chan struct{}), make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	// Test barrier: hold cleanup after unregister but before StateClose.
	// The normal budget leave callback never blocks. The monitor will close
	// this test's old ticket and return its reservation after cleanup resumes.
	ep.SetTimeWaitPolicy(nil, func() { close(removed); <-release })
	go func() { clock.Advance(60 * time.Second); close(expired) }()
	select {
	case <-removed:
	case <-time.After(time.Second):
		t.Fatal("cleanup barrier not reached")
	}
	p.openWith(1000, func(syn []byte) {
		injected := make(chan struct{})
		go func() { p.inject(syn); close(injected) }()
		select {
		case <-injected:
		case <-time.After(time.Second):
			t.Error("Handle waited on the closing endpoint")
		}
		unblock()
		<-expired
	})
	p.upload([]byte("replacement"))
	p.closeActive()
	if g := p.table.Stats(); g.Admitted != 2 || g.Rejected != 0 || p.dials.Load() != 2 {
		t.Fatal("SYN in removal/state gap was lost or readmitted", g)
	}
}

func TestTimeWaitClosingQueue(t *testing.T) {
	for _, late := range []bool{false, true} {
		name := "timer"
		if late {
			name = "closed_processor"
		}
		t.Run(name, func(t *testing.T) {
			clock := faketime.NewManualClock()
			o := ns.DefaultOptions()
			o.Clock = clock
			p := newPeerOptions(t, false, flows.Defaults(), o)
			p.open(1000)
			p.upload([]byte("old"))
			p.closeActive()
			id := gv.TransportEndpointID{LocalAddress: remoteAddr, LocalPort: 443, RemoteAddress: appAddr, RemotePort: p.port}
			ep := p.stack.FindTransportEndpoint(header.IPv4ProtocolNumber, tcp.ProtocolNumber, id, ns.NIC).(*tcp.Endpoint)
			// Finish the FIN transition, then stop the processor, not the clock.
			ep.LockUser()
			ep.UnlockUser()
			p.stack.Pause()
			paused := true
			defer func() {
				if paused {
					p.stack.Resume()
				}
			}()
			var calls atomic.Int32
			handler := func(_ gv.TransportEndpointID, pkt *gv.PacketBuffer) bool {
				calls.Add(1)
				if h := header.TCP(pkt.TransportHeader().Slice()); !h.Flags().Contains(header.TCPFlagSyn) {
					t.Error("hook received a non-SYN")
				}
				return false // A declined SYN must be dropped, never reset.
			}
			tcp.SetTimeWaitHandler(p.stack, handler)
			if late {
				// Finish both normal close drains with the hook still installed.
				// A demux lookup that captured ep can enqueue even after these.
				select {
				case <-p.current.relayClosed:
				case <-time.After(time.Second):
					t.Fatal("relay did not finish closing")
				}
				clock.Advance(60 * time.Second)
				if tcp.EndpointState(ep.State()) != tcp.StateClose {
					t.Fatal("timer did not close endpoint")
				}
			}
			queue := func(flags header.TCPFlags) {
				raw := p.packet(1000, p.ack, flags, nil)
				pkt := gv.NewPacketBuffer(gv.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
				defer pkt.DecRef()
				pkt.NetworkHeader().Consume(header.IPv4MinimumSize)
				pkt.TransportHeader().Consume(header.TCPMinimumSize)
				pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
				p.stack.TransportProtocolInstance(tcp.ProtocolNumber).(interface {
					QueuePacket(gv.TransportEndpoint, gv.TransportEndpointID, *gv.PacketBuffer)
				}).QueuePacket(ep, id, pkt)
			}
			queue(header.TCPFlagAck)
			queue(header.TCPFlagSyn)
			queue(header.TCPFlagSyn)
			queue(header.TCPFlagFin | header.TCPFlagAck)
			if !late {
				clock.Advance(60 * time.Second)
			}
			p.stack.Resume()
			paused = false
			deadline := time.Now().Add(time.Second)
			for calls.Load() == 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			// A delayed enqueue against the captured endpoint must also be silent.
			queue(header.TCPFlagSyn)
			if h := p.read(5 * time.Millisecond); h != nil {
				t.Fatalf("closed queue emitted flags %v", h.Flags())
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("hook calls = %d, want exactly 1", got)
			}
		})
	}
}
