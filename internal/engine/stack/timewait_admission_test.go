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
	"gvisor.dev/gvisor/pkg/tcpip/header"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
)

type finalACKBarrier struct {
	port             uint16
	ack              uint32
	entered, release chan struct{}
	once             sync.Once
}

type finalACKLink struct {
	*ns.Link
	barrier atomic.Pointer[finalACKBarrier]
}

func (l *finalACKLink) WritePackets(pkts gv.PacketBufferList) (int, tcpip.Error) {
	n, err := l.Link.WritePackets(pkts)
	if b := l.barrier.Load(); b != nil {
		for _, pkt := range pkts.AsSlice() {
			h := header.TCP(pkt.TransportHeader().Slice())
			if h.DestinationPort() == b.port && h.Flags() == header.TCPFlagAck && h.AckNumber() == b.ack {
				b.once.Do(func() { close(b.entered); <-b.release })
			}
		}
	}
	return n, err
}

func TestTimeWaitFinalACKReleasesAdmission(t *testing.T) {
	for _, cap := range []int{0, 1} {
		t.Run(fmt.Sprintf("cap_%d", cap), func(t *testing.T) {
			limits := flows.Defaults()
			limits.Flows, limits.PerApp, limits.TimeWait = 1, 1, cap
			link := &finalACKLink{Link: ns.NewLink()}
			p := newPeerLink(t, false, limits, ns.DefaultOptions(), link.Link, link)
			p.open(1000)
			p.upload([]byte("old"))
			barrier := &finalACKBarrier{port: p.port, ack: p.seq + 1, entered: make(chan struct{}), release: make(chan struct{})}
			unblock := sync.OnceFunc(func() { close(barrier.release) })
			defer unblock()
			link.barrier.Store(barrier)
			p.closeActive()
			select {
			case <-barrier.entered:
			case <-time.After(time.Second):
				t.Fatal("final ACK did not reach the output barrier")
			}
			// The app has seen its final ACK, but the old TCP processor is
			// still inside WritePackets. Admission must already be released.
			p.phase = "new tuple while old final ACK writer is paused"
			if g := p.table.Stats(); g.Flows != 0 || g.TimeWait != cap || g.TimeWaitSkipped != uint64(1-cap) {
				t.Error("final ACK exposed before admission release:", p.diagnostics())
			}
			p.port++
			p.openWith(500, func(syn []byte) {
				// Exercise admission itself while the output writer is paused.
				// Production ingress additionally fences the preceding FIN.
				pkt := gv.NewPacketBuffer(gv.PacketBufferOptions{Payload: buffer.MakeWithData(syn)})
				defer pkt.DecRef()
				pkt.NetworkHeader().Consume(header.IPv4MinimumSize)
				pkt.TransportHeader().Consume(header.TCPMinimumSize)
				pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
				pkt.NICID = ns.NIC
				p.forward.Handle(gv.TransportEndpointID{LocalAddress: remoteAddr, LocalPort: 443, RemoteAddress: appAddr, RemotePort: p.port}, pkt)
				unblock()
			})
			p.upload([]byte("replacement"))
			p.closeActive()
			if g := p.table.Stats(); g.Rejected != 0 || g.Admitted != 2 || p.dials.Load() != 2 {
				t.Fatal("released slot was not reusable:", p.diagnostics())
			}
		})
	}
}
