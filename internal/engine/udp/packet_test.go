package udp

import (
	"context"
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

func borrowed(raw []byte, source, destination netip.AddrPort) (stack.TransportEndpointID, *stack.PacketBuffer) {
	p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
	off := 20
	p.NetworkProtocolNumber = header.IPv4ProtocolNumber
	if source.Addr().Is6() {
		off = 40
		p.NetworkProtocolNumber = header.IPv6ProtocolNumber
	}
	p.NetworkHeader().Consume(off)
	p.TransportHeader().Consume(8)
	return stack.TransportEndpointID{RemoteAddress: tcpip.AddrFromSlice(source.Addr().AsSlice()), LocalAddress: tcpip.AddrFromSlice(destination.Addr().AsSlice()), RemotePort: source.Port(), LocalPort: destination.Port()}, p
}

func TestHandlerCopiesBorrowedPacket(t *testing.T) {
	gate := make(chan struct{})
	n, _, sockets, _, _, _ := setup(t, &testfake.Owners{Value: owner, Gate: gate})
	raw := packet.UDP(local, dest, []byte("original"))
	id, p := borrowed(raw, local, dest)
	if !n.Handle(id, p) {
		t.Fatal("UDP escaped handler")
	}
	for i := range raw {
		raw[i] = 0
	}
	p.DecRef()
	close(gate)
	s := await(t, sockets)
	if string(await(t, s.out).b) != "original" {
		t.Fatal("borrowed packet retained")
	}
}

func TestBadDatagramsAlwaysHandled(t *testing.T) {
	n, _, _, _, _, _ := setup(t, &testfake.Owners{Value: owner})
	for _, kind := range []string{"checksum", "length", "ipv6zero"} {
		src, dst := local, dest
		if kind == "ipv6zero" {
			src = netip.MustParseAddrPort("[2001:db8::2]:40000")
			dst = netip.MustParseAddrPort("[2001:db8::3]:3000")
		}
		raw := packet.UDP(src, dst, []byte("data"))
		off := 20
		if src.Addr().Is6() {
			off = 40
		}
		switch kind {
		case "checksum":
			raw[len(raw)-1] ^= 1
		case "length":
			raw[off+4], raw[off+5] = 0, 7
		case "ipv6zero":
			raw[off+6], raw[off+7] = 0, 0
		}
		id, p := borrowed(raw, src, dst)
		if !n.Handle(id, p) {
			t.Fatal("invalid packet escaped")
		}
		p.DecRef()
	}
	if n.Invalid.Load() != 3 {
		t.Fatal("validation or counting missing")
	}
}

func TestMissingGenerationNeverAdmitted(t *testing.T) {
	n, c, _, out, _, _ := setup(t, &testfake.Owners{Value: platform.Owner{AppID: "unknown"}})
	send(n, dest, []byte("test"))
	await(t, out)
	if c.Resolved.Load() != 0 {
		t.Fatal("unverifiable socket consumed policy sequence")
	}
	n.Reconcile(context.Background())
}
