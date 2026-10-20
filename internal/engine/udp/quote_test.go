package udp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func quoteFixture(v6, zeroChecksum bool, id uint16) (netip.AddrPort, netip.AddrPort, []byte, int, int) {
	src, dst := local, dest
	payload := []byte("original-body")
	if v6 {
		src, dst = netip.MustParseAddrPort("[2001:db8::2]:40000"), netip.MustParseAddrPort("[2001:db8::3]:3478")
		base := packet.UDP(src, dst, payload)
		raw := make([]byte, len(base)+16)
		copy(raw, base[:40])
		raw[0], raw[1], raw[2], raw[3] = 0x6a, 0xb1, 0x23, 0x45
		raw[6], raw[7] = 0, 37
		binary.BigEndian.PutUint16(raw[4:], uint16(len(raw)-40))
		copy(raw[40:48], []byte{60, 0, 1, 4, 0, 0, 0, 0})
		copy(raw[48:56], []byte{17, 0, 1, 4, 0, 0, 0, 0})
		copy(raw[56:], base[40:])
		return src, dst, raw, 56, len(payload)
	}
	base := packet.UDP(src, dst, payload)
	// Maximum IPv4 options, plus trailing IP padding outside UDP's length.
	raw := make([]byte, len(base)+40+4)
	copy(raw, base[:20])
	raw[0], raw[1], raw[8] = 0x4f, 0xbc, 37
	binary.BigEndian.PutUint16(raw[2:], uint16(len(raw)))
	binary.BigEndian.PutUint16(raw[4:], id)
	binary.BigEndian.PutUint16(raw[6:], 0x4000)
	for i := 20; i < 60; i++ {
		raw[i] = 1 // NOP options
	}
	copy(raw[60:], base[20:])
	if zeroChecksum {
		raw[66], raw[67] = 0, 0
	}
	raw[10], raw[11] = 0, 0
	binary.BigEndian.PutUint16(raw[10:], ^packet.Sum(raw[:60], 0))
	return src, dst, raw, 60, len(payload)
}

func quotePacket(raw []byte, netHeader int, src, dst netip.AddrPort) (stack.TransportEndpointID, *stack.PacketBuffer) {
	p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
	p.NetworkProtocolNumber = header.IPv4ProtocolNumber
	if src.Addr().Is6() {
		p.NetworkProtocolNumber = header.IPv6ProtocolNumber
	}
	p.NetworkHeader().Consume(netHeader)
	p.TransportHeader().Consume(8)
	id := stack.TransportEndpointID{RemoteAddress: tcpip.AddrFromSlice(src.Addr().AsSlice()), LocalAddress: tcpip.AddrFromSlice(dst.Addr().AsSlice()), RemotePort: src.Port(), LocalPort: dst.Port()}
	return id, p
}

func checkExactQuote(t *testing.T, got, original []byte, netHeader int, v6 bool) {
	t.Helper()
	src, dst, proto, off, total, ok := packet.IPHeader(got, false)
	if !ok || total != len(got) || len(got)-off < 8 {
		t.Fatalf("invalid enclosing ICMP packet: %x", got)
	}
	icmp := got[off:]
	initial := uint32(0)
	wantType, wantCode := byte(3), byte(3)
	want := original[:netHeader+8]
	if v6 {
		wantType, wantCode = 1, 4
		initial = packet.Pseudo(src, dst, 58, len(icmp))
		want = original
		if proto != 58 {
			t.Fatal("IPv6 rejection was not ICMPv6")
		}
	} else if proto != 1 {
		t.Fatal("IPv4 rejection was not ICMP")
	}
	if icmp[0] != wantType || icmp[1] != wantCode || packet.Sum(icmp, initial) != 65535 || !bytes.Equal(icmp[8:], want) {
		t.Fatalf("rejection changed its triggering headers: got %x want %x", icmp, want)
	}
}

func TestUDPRefusalsQuoteReceivedHeadersExactly(t *testing.T) {
	for _, mode := range []string{"admission", "policy"} {
		for _, kind := range []string{"ipv4-checksum", "ipv4-zero", "ipv6-extensions"} {
			t.Run(mode+"/"+kind, func(t *testing.T) {
				v6 := kind == "ipv6-extensions"
				gate := make(chan struct{})
				n, c, _, out, _, _ := setup(t, &testfake.Owners{Value: owner, Gate: gate})
				if mode == "admission" {
					c.Err = errors.New("capacity")
				} else {
					c.ResolveErr = errors.New("blocked line")
				}
				src, dst, raw, netHeader, _ := quoteFixture(v6, kind == "ipv4-zero", 13264)
				want := bytes.Clone(raw)
				id, p := quotePacket(raw, netHeader, src, dst)
				n.Handle(id, p)
				clear(raw) // quotation must outlive the borrowed packet
				p.DecRef()
				close(gate)
				checkExactQuote(t, await(t, out), want, netHeader, v6)
				// A retained rejection must quote this new triggering packet.
				src, dst, raw, netHeader, _ = quoteFixture(v6, kind == "ipv4-zero", 13265)
				want = bytes.Clone(raw)
				id, p = quotePacket(raw, netHeader, src, dst)
				n.Handle(id, p)
				p.DecRef()
				checkExactQuote(t, await(t, out), want, netHeader, v6)
				waitReplyState(t, func() bool { return c.Pending.Load() == 0 })
			})
		}
	}
}

func TestUDPVariableHeadersConsumeTheirExactPendingBudget(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, fit := range []bool{false, true} {
			t.Run(fmt.Sprintf("v6=%t/exact-fit=%t", v6, fit), func(t *testing.T) {
				gate := make(chan struct{})
				n, c, _, _, _, _ := setup(t, &testfake.Owners{Value: owner, Gate: gate})
				defer close(gate)
				src, dst, raw, netHeader, payloadSize := quoteFixture(v6, !v6, 13264)
				want := bytes.Clone(raw)
				owned := len(raw) + payloadSize
				c.Limit = int64(owned)
				if !fit {
					c.Limit--
				}
				id, p := quotePacket(raw, netHeader, src, dst)
				n.Handle(id, p)
				clear(raw)
				p.DecRef()
				if !fit {
					if n.Dropped.Load() != 1 || c.Pending.Load() != 0 {
						t.Fatalf("variable headers escaped the byte limit: pending=%d dropped=%d", c.Pending.Load(), n.Dropped.Load())
					}
					return
				}
				if c.Pending.Load() != int64(owned) {
					t.Fatalf("owned byte reservation=%d want %d", c.Pending.Load(), owned)
				}
				b := n.bucket(src)
				b.Lock()
				s := b.m[src]
				b.Unlock()
				s.mu.Lock()
				valid := len(s.queue) == 1 && len(s.queue[0].payload) == payloadSize && bytes.Equal(s.queue[0].original, want)
				s.mu.Unlock()
				if !valid {
					t.Fatal("queued payload or exact quotation was not retained independently")
				}
				n.Close()
				if c.Pending.Load() != 0 {
					t.Fatal("closing the queue leaked its header-byte reservation")
				}
			})
		}
	}
}
