package packet

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
)

func TestUDPRepliesFragmentAndReassembleWithChecksums(t *testing.T) {
	for _, family := range []struct {
		src, dst string
		maximum  int
	}{
		{"192.0.2.5:1234", "198.18.0.1:4321", 65507},
		{"[2001:db8::5]:1234", "[fdfe:dcba:9876::1]:4321", 65527},
	} {
		src, dst := netip.MustParseAddrPort(family.src), netip.MustParseAddrPort(family.dst)
		for _, size := range []int{0, 1, 12000, family.maximum - 1, family.maximum} {
			for _, mtu := range []int{1280, 9000} {
				t.Run(fmt.Sprintf("%s/%d/%d", src.Addr(), size, mtu), func(t *testing.T) {
					payload := make([]byte, size)
					for i := range payload {
						payload[i] = byte(i*131 + i/251)
					}
					const id = uint32(0x1234abcd)
					packets := UDPReply(src, dst, payload, mtu, id)
					if len(packets) == 0 {
						t.Fatal("representable UDP reply was dropped")
					}
					joined := make([]byte, size+8)
					seen := make([]bool, len(joined))
					wireBytes := 0
					for i := len(packets) - 1; i >= 0; i-- {
						p := packets[i]
						wireBytes += len(p)
						if len(p) > mtu {
							t.Fatalf("packet %d exceeds MTU: %d", i, len(p))
						}
						offset, header, more := 0, 20, false
						if src.Addr().Is4() {
							if p[0] != 0x45 || p[9] != 17 || int(binary.BigEndian.Uint16(p[2:])) != len(p) || Sum(p[:20], 0) != 65535 {
								t.Fatal("invalid IPv4 header")
							}
							flags := binary.BigEndian.Uint16(p[6:])
							offset, more = int(flags&0x1fff)*8, flags&0x2000 != 0
							if flags&0xc000 != 0 {
								t.Fatal("fragment has DF or reserved flag")
							}
							if len(packets) > 1 && binary.BigEndian.Uint16(p[4:]) != uint16(id&65535) {
								t.Fatal("IPv4 fragment ID changed")
							}
						} else {
							header = 40
							if p[0] != 0x60 || int(binary.BigEndian.Uint16(p[4:])) != len(p)-40 {
								t.Fatal("invalid IPv6 header")
							}
							if len(packets) > 1 {
								header = 48
								flags := binary.BigEndian.Uint16(p[42:])
								offset, more = int(flags&0xfff8), flags&1 != 0
								if p[6] != 44 || p[40] != 17 || p[41] != 0 || flags&6 != 0 || binary.BigEndian.Uint32(p[44:]) != id {
									t.Fatal("invalid IPv6 Fragment header")
								}
							} else if p[6] != 17 {
								t.Fatal("unneeded IPv6 extension header")
							}
						}
						body := p[header:]
						if more != (i != len(packets)-1) || (more && len(body)%8 != 0) || offset+len(body) > len(joined) {
							t.Fatal("invalid fragment extent")
						}
						for j := range body {
							if seen[offset+j] {
								t.Fatal("overlapping fragments")
							}
							seen[offset+j] = true
						}
						copy(joined[offset:], body)
					}
					for _, present := range seen {
						if !present {
							t.Fatal("fragment gap")
						}
					}
					if wireBytes != UDPReplySize(src.Addr(), dst.Addr(), size, mtu) {
						t.Fatal("byte reservation does not cover the owned packets")
					}
					if binary.BigEndian.Uint16(joined) != src.Port() || binary.BigEndian.Uint16(joined[2:]) != dst.Port() || int(binary.BigEndian.Uint16(joined[4:])) != len(joined) {
						t.Fatal("wrong reassembled UDP tuple or length")
					}
					if Sum(joined, Pseudo(src.Addr(), dst.Addr(), 17, len(joined))) != 65535 || sha256.Sum256(joined[8:]) != sha256.Sum256(payload) {
						t.Fatal("UDP checksum or payload hash changed")
					}
				})
			}
		}
		if UDPReplySize(src.Addr(), dst.Addr(), family.maximum+1, 9000) != 0 || UDPReply(src, dst, make([]byte, family.maximum+1), 9000, 1) != nil {
			t.Fatal("unrepresentable UDP payload accepted")
		}
		if UDP(src, dst, make([]byte, family.maximum)) == nil {
			t.Fatal("whole packet builder rejected a legal maximum")
		}
	}
}
