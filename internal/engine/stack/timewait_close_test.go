package stack_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

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
			if late {
				// Finish the relay's own Endpoint.Close before temporarily
				// disabling the hook. Otherwise that deferred Close can freeze
				// the queue after we reinstall the hook, before our late enqueue.
				select {
				case <-p.current.relayClosed:
				case <-time.After(time.Second):
					t.Fatal("relay did not finish closing")
				}
				// Leave an unfrozen closed endpoint using the stock close path.
				// A demux lookup that already captured ep can still enqueue here.
				tcp.SetTimeWaitHandler(p.stack, nil)
				clock.Advance(60 * time.Second)
				if tcp.EndpointState(ep.State()) != tcp.StateClose {
					t.Fatal("timer did not close endpoint")
				}
			}
			tcp.SetTimeWaitHandler(p.stack, handler)
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
