package packet

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

var builtPacket []byte

func TestUDPUsesOnlyReservedAllocation(t *testing.T) {
	for _, address := range []string{"192.0.2.1:1234", "[2001:db8::1]:1234"} {
		src := netip.MustParseAddrPort(address)
		dst := netip.AddrPortFrom(src.Addr(), 5678)
		payload := make([]byte, 8000)
		allocs := testing.AllocsPerRun(100, func() { builtPacket = UDP(src, dst, payload) })
		if allocs != 1 {
			t.Fatalf("%s: %v allocations, reserved one packet", src, allocs)
		}
		_, _, _, off, total, ok := IPHeader(builtPacket, false)
		if !ok || total != len(builtPacket) {
			t.Fatal("invalid IP header")
		}
		u := builtPacket[off:]
		if int(binary.BigEndian.Uint16(u[4:])) != len(u) || Sum(u, Pseudo(src.Addr(), dst.Addr(), 17, len(u))) != 65535 {
			t.Fatal("invalid UDP checksum or length")
		}
	}
	if UDP(netip.AddrPort{}, netip.AddrPort{}, nil) != nil {
		t.Fatal("accepted invalid addresses")
	}
}
