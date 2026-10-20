package packet

import (
	"encoding/binary"
	"net/netip"
)

type udpReplyLayout struct {
	header, chunk, count, bytes int
	fragmented                  bool
}

func replyLayout(src, dst netip.Addr, payload, mtu int) udpReplyLayout {
	if !src.IsValid() || !dst.IsValid() || src.Is4() != dst.Is4() || payload < 0 {
		return udpReplyLayout{}
	}
	header, maximum := 20, 65507
	if src.Is6() {
		header, maximum = 40, 65527
	}
	if payload > maximum || mtu < header+8 {
		return udpReplyLayout{}
	}
	transport := payload + 8
	if header+transport <= mtu {
		return udpReplyLayout{header: header, chunk: transport, count: 1, bytes: header + transport}
	}
	if src.Is6() {
		header += 8
	}
	chunk := (mtu - header) &^ 7
	if chunk < 8 {
		return udpReplyLayout{}
	}
	count := (transport + chunk - 1) / chunk
	return udpReplyLayout{header: header, chunk: chunk, count: count, bytes: transport + count*header, fragmented: true}
}

// UDPReplySize is the owned wire storage required for the reply, including
// every fragment's headers. Zero means it cannot be represented. Callers
// reserve these bytes before UDPReply allocates any packet storage.
func UDPReplySize(src, dst netip.Addr, payload, mtu int) int {
	return replyLayout(src, dst, payload, mtu).bytes
}

// UDPReply builds one UDP datagram, fragmented only when it exceeds the TUN
// MTU. IPv6 fragmentation is legitimate here: the engine originates this
// host-facing packet. The UDP checksum covers the complete reassembled body.
func UDPReply(src, dst netip.AddrPort, payload []byte, mtu int, id uint32) [][]byte {
	layout := replyLayout(src.Addr(), dst.Addr(), len(payload), mtu)
	if layout.bytes == 0 {
		return nil
	}
	var udp [8]byte
	binary.BigEndian.PutUint16(udp[:], src.Port())
	binary.BigEndian.PutUint16(udp[2:], dst.Port())
	binary.BigEndian.PutUint16(udp[4:], uint16(len(payload)+8))
	partial := Sum(udp[:], Pseudo(src.Addr(), dst.Addr(), 17, len(payload)+8))
	checksum := ^Sum(payload, uint32(partial))
	if checksum == 0 {
		checksum = 65535
	}
	binary.BigEndian.PutUint16(udp[6:], checksum)
	storage := make([]byte, layout.bytes)
	packets := make([][]byte, 0, layout.count)
	position := 0
	for from := 0; from < len(payload)+8; from += layout.chunk {
		to := min(from+layout.chunk, len(payload)+8)
		length := layout.header + to - from
		b := storage[position : position+length : position+length]
		position += length
		protocol := byte(17)
		if layout.fragmented && src.Addr().Is6() {
			protocol = 44
		}
		writeIPHeader(b, src.Addr(), dst.Addr(), protocol)
		if layout.fragmented {
			more := to < len(payload)+8
			if src.Addr().Is4() {
				binary.BigEndian.PutUint16(b[4:], uint16(id))
				flags := uint16(from / 8)
				if more {
					flags |= 0x2000
				}
				binary.BigEndian.PutUint16(b[6:], flags)
				b[10], b[11] = 0, 0
				binary.BigEndian.PutUint16(b[10:], ^Sum(b[:20], 0))
			} else {
				b[40] = 17
				flags := uint16(from)
				if more {
					flags |= 1
				}
				binary.BigEndian.PutUint16(b[42:], flags)
				binary.BigEndian.PutUint32(b[44:], id)
			}
		}
		body := b[layout.header:]
		if from == 0 {
			copy(body, udp[:])
			copy(body[8:], payload[:to-8])
		} else {
			copy(body, payload[from-8:to-8])
		}
		packets = append(packets, b)
	}
	return packets
}
