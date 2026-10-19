//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type tcpObservation struct {
	At            int64  `json:"at"`
	Direction     string `json:"direction"`
	Source        uint16 `json:"source"`
	Target        uint16 `json:"target"`
	Flags         byte   `json:"flags"`
	Sequence      uint32 `json:"sequence"`
	Ack           uint32 `json:"ack"`
	Payload       int    `json:"payloadBytes"`
	Window        uint16 `json:"window"`
	IPChecksumOK  bool   `json:"ipChecksumOK"`
	TCPChecksumOK bool   `json:"tcpChecksumOK"`
	Header        string `json:"header"`
}

// A short header-only tail makes passive-close failures diagnosable without a
// large packet capture or collecting application payloads.
func (g *gateway) trace(packet []byte, direction string) {
	if len(packet) < 40 || packet[0]>>4 != 4 || packet[9] != 6 {
		return
	}
	if net.IP(packet[12:16]).String() != "198.19.128.2" && net.IP(packet[16:20]).String() != "198.19.128.2" {
		return
	}
	offset := int(packet[0]&15) * 4
	if offset < 20 || offset+20 > len(packet) {
		return
	}
	tcp := packet[offset:]
	item := tcpObservation{At: time.Now().UnixMicro(), Direction: direction, Source: binary.BigEndian.Uint16(tcp), Target: binary.BigEndian.Uint16(tcp[2:]), Flags: tcp[13], Sequence: binary.BigEndian.Uint32(tcp[4:]), Ack: binary.BigEndian.Uint32(tcp[8:])}
	item.Payload = len(tcp) - int(tcp[12]>>4)*4
	item.Window = binary.BigEndian.Uint16(tcp[14:])
	item.IPChecksumOK = checksum.Checksum(packet[:offset], 0) == 0xffff
	pseudo := header.PseudoHeaderChecksum(6, tcpip.AddrFromSlice(packet[12:16]), tcpip.AddrFromSlice(packet[16:20]), uint16(len(tcp)))
	item.TCPChecksumOK = checksum.Checksum(tcp, pseudo) == 0xffff
	if h := int(tcp[12]>>4) * 4; h >= 20 && h <= len(tcp) {
		item.Header = fmt.Sprintf("%x", tcp[:h])
	}
	if direction != "delivered" {
		g.diag.Lock()
		if g.diag.wire == nil {
			g.diag.wire = make(map[string]uint64)
		}
		g.diag.wire[direction+"-segments"]++
		if item.Flags&2 != 0 {
			if item.Flags&16 != 0 {
				g.diag.wire[direction+"-synack"]++
			} else {
				g.diag.wire[direction+"-syn"]++
			}
		}
		if item.Flags&1 != 0 {
			g.diag.wire[direction+"-fin"]++
		}
		g.diag.Unlock()
	}
	g.states()
	g.event("packet-"+direction, 0, fmt.Sprintf("%d -> %d", item.Source, item.Target),
		fmt.Sprintf("flags=%02x seq=%d ack=%d bytes=%d ipOK=%t tcpOK=%t window=%d", item.Flags, item.Sequence, item.Ack, item.Payload, item.IPChecksumOK, item.TCPChecksumOK, item.Window))
	g.stats.Lock()
	defer g.stats.Unlock()
	if len(g.stats.TCPTrace) == 256 {
		copy(g.stats.TCPTrace, g.stats.TCPTrace[1:])
		g.stats.TCPTrace = g.stats.TCPTrace[:255]
	}
	g.stats.TCPTrace = append(g.stats.TCPTrace, item)
}
