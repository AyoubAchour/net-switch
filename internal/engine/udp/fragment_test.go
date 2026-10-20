package udp

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
	gu "gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type fragmentSocket struct {
	*socket
	df chan bool
}

func (s *fragmentSocket) WriteTo(b []byte, a netip.AddrPort, df bool) (int, error) {
	s.df <- df
	return len(b), nil
}

func TestIPv6FragmentIntentSurvivesReassembly(t *testing.T) {
	for _, fragmented := range []bool{false, true} {
		t.Run(map[bool]string{false: "unfragmented-needs-PTB", true: "host-already-fragmented"}[fragmented], func(t *testing.T) {
			conn := &fragmentSocket{socket: newSocket(), df: make(chan bool, 1)}
			d := testfake.Dialer{UDPFunc: func(context.Context, string, bool) (platform.UDPConn, error) { return conn, nil }}
			link := ns.NewLink()
			s, err := ns.New(link, ns.DefaultOptions())
			if err != nil {
				t.Fatal(err)
			}
			defer s.Wait()
			defer s.Close()
			n := New(context.Background(), s, &testfake.Controller{Line: "A"}, &testfake.Owners{Value: owner}, nil, d, testfake.Output{Packets: make(chan []byte, 16)}, 9000)
			defer n.Close()
			raw := packet.UDP(netip.MustParseAddrPort("[fdfe:dcba:9876::2]:40000"), netip.MustParseAddrPort("[2001:db8::1]:3478"), []byte("0123456789abcdef"))
			packets := [][]byte{raw}
			if fragmented {
				fragment := func(from, to int, more bool) []byte {
					b := make([]byte, 48+to-from)
					copy(b, raw[:40])
					b[6] = 44
					binary.BigEndian.PutUint16(b[4:], uint16(len(b)-40))
					b[40] = 17
					flags := uint16(from)
					if more {
						flags |= 1
					}
					binary.BigEndian.PutUint16(b[42:], flags)
					binary.BigEndian.PutUint32(b[44:], 1234)
					copy(b[48:], raw[40+from:40+to])
					return b
				}
				packets = [][]byte{fragment(16, 24, false), fragment(0, 16, true)}
			}
			for _, b := range packets {
				p := gv.NewPacketBuffer(gv.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
				link.InjectInbound(header.IPv6ProtocolNumber, p)
				p.DecRef()
			}
			if df := await(t, conn.df); df == fragmented {
				t.Fatalf("fragmented=%v was forwarded with DF=%v", fragmented, df)
			}
		})
	}
}

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
