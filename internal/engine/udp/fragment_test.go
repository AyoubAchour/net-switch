package udp

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
	gu "gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func TestReorderedIPv4FragmentsValidateAfterReassembly(t *testing.T) {
	n, _, sockets, _, _, _ := setup(t, &testfake.Owners{Value: owner})
	link := ns.NewLink()
	s, err := ns.New(link, ns.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Wait()
	defer s.Close()
	s.SetTransportProtocolHandler(gu.ProtocolNumber, n.Handle)
	raw := packet.UDP(local, dest, []byte("0123456789abcdef"))
	fragment := func(from, to, flags int) []byte {
		b := append(append([]byte(nil), raw[:20]...), raw[20+from:20+to]...)
		binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
		binary.BigEndian.PutUint16(b[4:], 1234)
		binary.BigEndian.PutUint16(b[6:], uint16(flags))
		b[10], b[11] = 0, 0
		binary.BigEndian.PutUint16(b[10:], ^packet.Sum(b[:20], 0))
		return b
	}
	for _, b := range [][]byte{fragment(16, 24, 2), fragment(0, 16, 0x2000)} {
		p := gv.NewPacketBuffer(gv.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
		link.InjectInbound(header.IPv4ProtocolNumber, p)
		p.DecRef()
	}
	remote := await(t, sockets)
	if got := await(t, remote.out); string(got.b) != "0123456789abcdef" {
		t.Fatal("fragmented payload corrupted")
	}
	if n.Invalid.Load() != 0 {
		t.Fatal("checksum checked before reassembly")
	}
	n.Reconcile(context.Background())
}
