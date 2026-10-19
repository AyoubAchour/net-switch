package tcp

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

type heldSweepEndpoint struct {
	tcpip.Endpoint
	once             sync.Once
	entered, release chan struct{}
	visits           atomic.Int32
}

func (e *heldSweepEndpoint) State() uint32 {
	e.once.Do(func() { close(e.entered); <-e.release })
	e.visits.Add(1)
	return uint32(gtcp.StateEstablished)
}

func TestHandleDuring65536FlowSweep(t *testing.T) {
	l := ns.NewLink()
	s, err := ns.New(l, ns.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close(); s.Wait(); l.Close() }()
	control := &testfake.Controller{}
	f := &Forwarder{ctx: context.Background(), stack: s, control: control, out: l, inFlight: 2,
		pending: map[gv.TransportEndpointID]*pendingOpen{}, connections: map[gv.TransportEndpointID]*connection{}}
	// Upstream's zero-cap silent drop completes admission without a dial.
	f.forwarder = gtcp.NewForwarder(s, MinimumBuffer, 0, func(*gtcp.ForwarderRequest) { t.Error("unexpected dial") })
	ep := &heldSweepEndpoint{entered: make(chan struct{}), release: make(chan struct{})}
	for i := range 65536 {
		id := gv.TransportEndpointID{RemotePort: uint16(i)}
		f.connections[id] = &connection{id: id, ep: ep}
	}
	swept := make(chan struct{})
	go func() { f.sweep(time.Now()); close(swept) }()
	<-ep.entered
	defer func() { close(ep.release); <-swept }()
	src := tcpip.AddrFrom4([4]byte{198, 18, 0, 2})
	dst := tcpip.AddrFrom4([4]byte{203, 0, 113, 7})
	raw := make([]byte, 40)
	ip := header.IPv4(raw)
	ip.Encode(&header.IPv4Fields{TotalLength: 40, TTL: 64, Protocol: uint8(gtcp.ProtocolNumber), SrcAddr: src, DstAddr: dst})
	ip.SetChecksum(^ip.CalculateChecksum())
	h := header.TCP(raw[20:])
	h.Encode(&header.TCPFields{SrcPort: 40000, DstPort: 443, SeqNum: 1000, DataOffset: 20, Flags: header.TCPFlagSyn, WindowSize: 65535})
	h.SetChecksum(^checksum.Checksum(h, header.PseudoHeaderChecksum(gtcp.ProtocolNumber, src, dst, uint16(len(h)))))
	pkt := gv.NewPacketBuffer(gv.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
	defer pkt.DecRef()
	pkt.NetworkHeader().Consume(20)
	pkt.TransportHeader().Consume(20)
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	id := gv.TransportEndpointID{RemoteAddress: src, LocalAddress: dst, RemotePort: 40000, LocalPort: 443}
	handled := make(chan bool, 1)
	go func() { handled <- f.Handle(id, pkt) }()
	select {
	case ok := <-handled:
		if !ok || control.Begun.Load() != 1 || control.Closed.Load() != 1 {
			t.Fatal("Handle did not finish admission")
		}
	case <-time.After(time.Second):
		t.Fatal("Handle stalled behind the sweep")
	}
	t.Cleanup(func() {
		if ep.visits.Load() != 65536 {
			t.Fatal("sweep did not visit all 65,536 flows", ep.visits.Load())
		}
	})
	t.Log("Handle completed admission while the 65,536-flow sweep was held inside endpoint work")
}
