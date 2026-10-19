//go:build windows

package main

import (
	"encoding/binary"
	"net"
	"time"
)

type tcpObservation struct {
	At        int64  `json:"at"`
	Direction string `json:"direction"`
	Source    uint16 `json:"source"`
	Target    uint16 `json:"target"`
	Flags     byte   `json:"flags"`
	Sequence  uint32 `json:"sequence"`
	Ack       uint32 `json:"ack"`
	Payload   int    `json:"payloadBytes"`
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
	g.stats.Lock()
	defer g.stats.Unlock()
	if len(g.stats.TCPTrace) == 64 {
		copy(g.stats.TCPTrace, g.stats.TCPTrace[1:])
		g.stats.TCPTrace = g.stats.TCPTrace[:63]
	}
	g.stats.TCPTrace = append(g.stats.TCPTrace, item)
}
