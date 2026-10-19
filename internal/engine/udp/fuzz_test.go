package udp

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func FuzzUDPHandler(f *testing.F) {
	f.Add(packet.UDP(local, dest, []byte("seed")), false, true)
	f.Add(packet.UDP(local, dest, []byte("rejected")), false, false)
	f.Add(packet.UDP(netip.MustParseAddrPort("[2001:db8::1]:40000"), netip.MustParseAddrPort("[2001:db8::2]:80"), []byte("v6")), true, true)
	f.Fuzz(func(t *testing.T, raw []byte, v6, accept bool) {
		off := 20
		protocol := header.IPv4ProtocolNumber
		src, dst := local, dest
		if v6 {
			off = 40
			protocol = header.IPv6ProtocolNumber
			src = netip.MustParseAddrPort("[2001:db8::1]:40000")
			dst = netip.MustParseAddrPort("[2001:db8::2]:80")
		}
		if len(raw) < off+8 || len(raw) > 65535 {
			return
		}
		control := &testfake.Controller{Limit: 32 << 20}
		if !accept {
			control.Err = errors.New("capacity")
		}
		out := testfake.Output{Packets: make(chan []byte, 1)}
		gate := make(chan struct{})
		dialer := testfake.Dialer{UDPFunc: func(context.Context, string, bool) (platform.UDPConn, error) { return newSocket(), nil }}
		n := New(context.Background(), nil, control, &testfake.Owners{Value: owner, Gate: gate}, nil, dialer, out, 9000)
		defer n.Close()
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), raw...))})
		defer p.DecRef()
		p.NetworkProtocolNumber = protocol
		p.NetworkHeader().Consume(off)
		p.TransportHeader().Consume(8)
		id := stack.TransportEndpointID{RemoteAddress: tcpip.AddrFromSlice(src.Addr().AsSlice()), LocalAddress: tcpip.AddrFromSlice(dst.Addr().AsSlice()), RemotePort: src.Port(), LocalPort: dst.Port()}
		if !n.Handle(id, p) {
			t.Fatal("NAT declined datagram")
		}
		// Keep lookup pending while duplicate datagrams exercise queue limits.
		for range 70 {
			n.Handle(id, p)
		}
		close(gate)
		n.Close()
		if control.Pending.Load() != 0 {
			t.Fatal("fuzz path leaked bytes")
		}
	})
}
