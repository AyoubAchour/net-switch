package packet

import (
	"net/netip"
	"testing"
)

func FuzzPackets(f *testing.F) {
	a := netip.MustParseAddrPort("198.18.0.2:40000")
	b := netip.MustParseAddrPort("203.0.113.7:3478")
	f.Add(UDP(a, b, []byte("seed")))
	f.Add(Unreachable(UDP(a, b, []byte("seed")), 1400))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65535 {
			return
		}
		IPHeader(b, false)
		IPHeader(b, true)
		AppUnreachable(b)
		reply := Unreachable(b, 1280)
		if len(reply) > 0 {
			if _, _, _, _, _, ok := IPHeader(reply, false); !ok {
				t.Fatal("constructed invalid ICMP reply")
			}
		}
	})
}
