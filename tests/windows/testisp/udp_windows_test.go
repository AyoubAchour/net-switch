//go:build windows

package main

import (
	"bytes"
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
			if len(packet) > 1500 || int(ip.TotalLength()) != len(packet) || checksum.Checksum(packet[:20], 0) != 0xffff { t.Fatalf("size %d invalid IP fragment", size) }
			if int(ip.FragmentOffset()) != len(transport) { t.Fatalf("size %d overlapping or missing fragment", size) }
			if (ip.Flags()&header.IPv4FlagMoreFragments != 0) != (i < len(packets)-1) { t.Fatal("wrong last fragment") }
			transport = append(transport, packet[20:]...)
		}
		udp := header.UDP(transport)
		if udp.SourcePort() != 12345 || udp.DestinationPort() != 54321 || int(udp.Length()) != size+8 { t.Fatal("wrong UDP tuple or length") }
		if !bytes.Equal(transport[8:], payload) { t.Fatal("payload corruption") }
		pseudo := header.PseudoHeaderChecksum(header.UDPProtocolNumber, source, destination, uint16(len(transport)))
		if checksum.Checksum(transport, pseudo) != 0xffff { t.Fatal("invalid UDP checksum") }
	}
}
