//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestUDPRepliesFragmentAndChecksum(t *testing.T) {
	source := tcpip.AddrFrom4([4]byte{198, 19, 128, 2})
	destination := tcpip.AddrFrom4([4]byte{198, 19, 0, 1})
	for _, size := range []int{0, 64, 1472, 1473, 8192, 65507} {
		payload := bytes.Repeat([]byte{0x5a}, size)
		packets := udpReplies(source, destination, 12345, 54321, payload)
		var transport []byte
		for i, packet := range packets {
			ip := header.IPv4(packet)
			if len(packet) > 1500 || int(ip.TotalLength()) != len(packet) || checksum.Checksum(packet[:20], 0) != 0xffff {
				t.Fatalf("size %d invalid IP fragment", size)
			}
			if int(ip.FragmentOffset()) != len(transport) {
				t.Fatalf("size %d overlapping or missing fragment", size)
			}
			if (ip.Flags()&header.IPv4FlagMoreFragments != 0) != (i < len(packets)-1) {
				t.Fatal("wrong last fragment")
			}
			transport = append(transport, packet[20:]...)
		}
		udp := header.UDP(transport)
		if udp.SourcePort() != 12345 || udp.DestinationPort() != 54321 || int(udp.Length()) != size+8 {
			t.Fatal("wrong UDP tuple or length")
		}
		if !bytes.Equal(transport[8:], payload) {
			t.Fatal("payload corruption")
		}
		pseudo := header.PseudoHeaderChecksum(header.UDPProtocolNumber, source, destination, uint16(len(transport)))
		if checksum.Checksum(transport, pseudo) != 0xffff {
			t.Fatal("invalid UDP checksum")
		}
	}
}

func TestUDPRepliesIPv6Fragments(t *testing.T) {
	source := tcpip.AddrFrom16([16]byte{0x20, 1, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	destination := tcpip.AddrFrom16([16]byte{0x20, 1, 0x0d, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	for _, size := range []int{64, 1200, 1800, 8192} {
		payload := bytes.Repeat([]byte{0xa5}, size)
		var transport []byte
		for _, packet := range udpReplies(source, destination, 10000, 20000, payload) {
			if len(packet) > 1500 || len(packet) != 40+int(binary.BigEndian.Uint16(packet[4:6])) {
				t.Fatal("invalid IPv6 length")
			}
			if packet[6] == 44 {
				offset := int(binary.BigEndian.Uint16(packet[42:44]) & 0xfff8)
				if offset != len(transport) {
					t.Fatal("IPv6 fragment gap or overlap")
				}
				transport = append(transport, packet[48:]...)
			} else {
				transport = append(transport, packet[40:]...)
			}
		}
		if !bytes.Equal(transport[8:], payload) {
			t.Fatal("IPv6 payload corrupted")
		}
		pseudo := header.PseudoHeaderChecksum(header.UDPProtocolNumber, source, destination, uint16(len(transport)))
		if checksum.Checksum(transport, pseudo) != 0xffff {
			t.Fatal("invalid IPv6 UDP checksum")
		}
	}
}
