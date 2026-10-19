// Package packet builds bounded replies. Parsing the packet path never trusts
// lengths supplied by the peer.
package packet

import (
	"encoding/binary"
	"net/netip"
)

func Sum(b []byte, initial uint32) uint16 {
	s := initial
	for len(b) >= 2 {
		s += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) != 0 {
		s += uint32(b[0]) << 8
	}
	for s>>16 != 0 {
		s = (s & 65535) + (s >> 16)
	}
	return uint16(s)
}

func Pseudo(src, dst netip.Addr, protocol byte, length int) uint32 {
	s := uint32(Sum(src.AsSlice(), 0)) + uint32(Sum(dst.AsSlice(), 0)) + uint32(protocol)
	s += uint32(length&65535) + uint32(length>>16)
	return s
}

func IP(src, dst netip.Addr, protocol byte, payload []byte) []byte {
	b, body := allocateIP(src, dst, protocol, len(payload))
	copy(body, payload)
	return b
}

func allocateIP(src, dst netip.Addr, protocol byte, length int) ([]byte, []byte) {
	if !src.IsValid() || !dst.IsValid() || src.Is4() != dst.Is4() || length < 0 || length > 65515 {
		return nil, nil
	}
	n := 20
	if src.Is6() {
		n = 40
	}
	b := make([]byte, n+length)
	if n == 20 {
		b[0], b[8], b[9] = 0x45, 64, protocol
		binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
		copy(b[12:16], src.AsSlice())
		copy(b[16:20], dst.AsSlice())
		binary.BigEndian.PutUint16(b[10:], ^Sum(b[:20], 0))
	} else {
		b[0], b[6], b[7] = 0x60, protocol, 64
		binary.BigEndian.PutUint16(b[4:], uint16(length))
		copy(b[8:24], src.AsSlice())
		copy(b[24:40], dst.AsSlice())
	}
	return b, b[n:]
}

func Reset(src, dst netip.AddrPort, seq, ack uint32, ackFlag bool) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b, src.Port())
	binary.BigEndian.PutUint16(b[2:], dst.Port())
	binary.BigEndian.PutUint32(b[4:], seq)
	binary.BigEndian.PutUint32(b[8:], ack)
	b[12], b[13] = 5<<4, 4
	if ackFlag {
		b[13] |= 16
	}
	binary.BigEndian.PutUint16(b[16:], ^Sum(b, Pseudo(src.Addr(), dst.Addr(), 6, len(b))))
	return IP(src.Addr(), dst.Addr(), 6, b)
}
