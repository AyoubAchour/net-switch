package packet

import (
	"encoding/binary"
	"net/netip"
)

func UDP(src, dst netip.AddrPort, payload []byte) []byte {
	maximum := 65507
	if src.Addr().Is6() {
		maximum = 65527
	}
	if len(payload) > maximum {
		return nil
	}
	// Build directly in the final allocation: the pending-byte reservation
	// covers a payload copy and this packet, with no temporary third copy.
	raw, b := allocateIP(src.Addr(), dst.Addr(), 17, 8+len(payload))
	if raw == nil {
		return nil
	}
	binary.BigEndian.PutUint16(b, src.Port())
	binary.BigEndian.PutUint16(b[2:], dst.Port())
	binary.BigEndian.PutUint16(b[4:], uint16(len(b)))
	copy(b[8:], payload)
	cs := ^Sum(b, Pseudo(src.Addr(), dst.Addr(), 17, len(b)))
	if cs == 0 {
		cs = 65535
	}
	binary.BigEndian.PutUint16(b[6:], cs)
	return raw
}

// IPHeader accepts a truncated quotation only when quoted is true. Fragment
// payloads are left to gVisor's reassembly, never pre-validated as UDP.
func IPHeader(b []byte, quoted bool) (src, dst netip.Addr, proto byte, offset, total int, ok bool) {
	if len(b) < 1 {
		return
	}
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return
		}
		offset = int(b[0]&15) * 4
		total = int(binary.BigEndian.Uint16(b[2:]))
		if offset < 20 || offset > len(b) || total < offset || (!quoted && total > len(b)) || binary.BigEndian.Uint16(b[6:])&0x3fff != 0 || Sum(b[:offset], 0) != 65535 {
			return
		}
		src = netip.AddrFrom4([4]byte(b[12:16]))
		dst = netip.AddrFrom4([4]byte(b[16:20]))
		proto = b[9]
	case 6:
		if len(b) < 40 {
			return
		}
		offset = 40
		total = 40 + int(binary.BigEndian.Uint16(b[4:]))
		if !quoted && total > len(b) {
			return
		}
		src = netip.AddrFrom16([16]byte(b[8:24]))
		dst = netip.AddrFrom16([16]byte(b[24:40]))
		proto = b[6]
		// The ICMP observer needs only ordinary replies we constructed, with
		// no extension headers. All general IPv6 input goes through gVisor.
	default:
		return
	}
	ok = true
	return
}

func Unreachable(original []byte, mtu uint32) []byte {
	src, dst, _, off, total, ok := IPHeader(original, false)
	if !ok {
		return nil
	}
	limit := off + 8
	proto := byte(1)
	typ, code := byte(3), byte(3)
	if src.Is6() {
		limit = min(total, 1232)
		proto = 58
		typ, code = 1, 4
	}
	if mtu != 0 {
		if src.Is4() {
			code = 4
		} else {
			typ, code = 2, 0
		}
	}
	quote := original[:min(total, limit)]
	b := make([]byte, 8+len(quote))
	b[0], b[1] = typ, code
	if mtu != 0 {
		if src.Is4() {
			binary.BigEndian.PutUint16(b[6:], uint16(min(mtu, 65535)))
		} else {
			binary.BigEndian.PutUint32(b[4:], mtu)
		}
	}
	copy(b[8:], quote)
	var initial uint32
	if src.Is6() {
		initial = Pseudo(dst, src, 58, len(b))
	}
	binary.BigEndian.PutUint16(b[2:], ^Sum(b, initial))
	return IP(dst, src, proto, b)
}

// AppUnreachable validates both enclosing checksums and the quoted tuple.
// A quote describes a reply: its destination is the app's local endpoint.
func AppUnreachable(b []byte) (netip.AddrPort, bool) {
	src, dst, proto, off, total, ok := IPHeader(b, false)
	if !ok || total-off < 8 {
		return netip.AddrPort{}, false
	}
	h := b[off:total]
	var initial uint32
	if src.Is4() {
		if proto != 1 || h[0] != 3 || h[1] != 3 {
			return netip.AddrPort{}, false
		}
	} else {
		if proto != 58 || h[0] != 1 || h[1] != 4 {
			return netip.AddrPort{}, false
		}
		initial = Pseudo(src, dst, 58, len(h))
	}
	if Sum(h, initial) != 65535 {
		return netip.AddrPort{}, false
	}
	q := h[8:]
	qs, qd, qp, qo, qt, ok := IPHeader(q, true)
	if !ok || qp != 17 || len(q) < qo+8 || qt < qo+8 || qd != src || qs != dst {
		return netip.AddrPort{}, false
	}
	u := q[qo:]
	if int(binary.BigEndian.Uint16(u[4:])) != qt-qo || binary.BigEndian.Uint16(u[4:]) < 8 {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(qd, binary.BigEndian.Uint16(u[2:])), true
}
