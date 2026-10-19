//go:build windows

package main

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type datagram struct { destination string; payload []byte }
type udpSession struct { packets chan datagram }

// One unconnected socket per source, so the harness does not change the STUN
// mapping or suppress a reply from a previously uncontacted destination.
func (g *gateway) udpHandler(link *channel.Endpoint) func(stack.TransportEndpointID, *stack.PacketBuffer) bool {
	var mu sync.Mutex
	sessions := make(map[string]*udpSession)
	return func(id stack.TransportEndpointID, packet *stack.PacketBuffer) bool {
		if packet.NetworkProtocolNumber != header.IPv4ProtocolNumber { return true }
		h := header.UDP(packet.TransportHeader().Slice())
		if len(h) < header.UDPMinimumSize { return true }
		validLength, validChecksum := header.UDPValid(h, func() uint16 { return packet.Data().Checksum() }, uint16(packet.Data().Size()), packet.NetworkProtocolNumber, id.RemoteAddress, id.LocalAddress, false)
		if !validLength || !validChecksum { return true }
		key := net.JoinHostPort(id.RemoteAddress.String(), portString(id.RemotePort))
		destination := net.JoinHostPort(id.LocalAddress.String(), portString(id.LocalPort))
		mu.Lock()
		session := sessions[key]
		if session == nil {
			if len(sessions) >= 4096 { mu.Unlock(); return true }
			session = &udpSession{packets:make(chan datagram, 64)}
			sessions[key] = session
			go func() {
				defer func() { mu.Lock(); if sessions[key] == session { delete(sessions, key) }; mu.Unlock() }()
				g.udpRelay(link, id.RemoteAddress, id.RemotePort, session)
			}()
		}
		mu.Unlock()
		payload := append([]byte(nil), packet.Data().AsRange().Capped(int(h.Length())-8).ToSlice()...)
		select { case session.packets <- datagram{destination, payload}: default: g.stats.Lock(); g.stats.TestISP.Dropped++; g.stats.Unlock() }
		return true
	}
}

func portString(port uint16) string {
	return strconv.Itoa(int(port))
}

func (g *gateway) udpRelay(link *channel.Endpoint, app tcpip.Address, port uint16, session *udpSession) {
	config := net.ListenConfig{Control:bindInterface(g.index)}
	remote, err := config.ListenPacket(context.Background(), "udp4", net.JoinHostPort(g.uplinkIP.String(), "0"))
	if err != nil { g.failure("UDP bind", err); return }
	defer remote.Close()
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		packet := make([]byte, 65507)
		for {
			remote.SetReadDeadline(time.Now().Add(30*time.Second))
			n, peer, err := remote.ReadFrom(packet); if err != nil { return }
			g.transferred(int64(n), false)
			address := peer.(*net.UDPAddr)
			source := address.IP.To4()
			g.targetMu.RLock()
			for virtual, backend := range g.targets {
				if backend == address.String() { host, _, _ := net.SplitHostPort(virtual); source = net.ParseIP(host).To4(); break }
			}
			g.targetMu.RUnlock()
			for _, reply := range udpReplies(tcpip.AddrFromSlice(source), app, uint16(address.Port), port, packet[:n]) {
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload:buffer.MakeWithData(reply)})
				var packets stack.PacketBufferList; packets.PushBack(pkt)
				if written, _ := link.WritePackets(packets); written != 1 { g.stats.Lock(); g.stats.TestISP.Dropped++; g.stats.Unlock() }
				pkt.DecRef()
			}
		}
	}()
	first := true
	for {
		select {
		case <-g.done: return
		case <-closed: return
		case packet := <-session.packets:
			if first { g.record(packet.destination); first = false } else { g.stats.Lock(); g.stats.Destinations[packet.destination]++; g.stats.Unlock() }
			address, err := net.ResolveUDPAddr("udp4", g.backend(packet.destination))
			if err != nil { g.failure(packet.destination, err); continue }
			if n, err := remote.WriteTo(packet.payload, address); err != nil { g.failure(packet.destination, err) } else { g.transferred(int64(n), true) }
		}
	}
}

var packetID atomic.Uint32

func udpReplies(source, destination tcpip.Address, sourcePort, destinationPort uint16, payload []byte) [][]byte {
	transport := make([]byte, 8+len(payload))
	h := header.UDP(transport)
	h.Encode(&header.UDPFields{SrcPort:sourcePort, DstPort:destinationPort, Length:uint16(len(transport))})
	copy(transport[8:], payload)
	pseudo := header.PseudoHeaderChecksum(header.UDPProtocolNumber, source, destination, uint16(len(transport)))
	sum := ^checksum.Checksum(transport, pseudo); if sum == 0 { sum = 0xffff }; h.SetChecksum(sum)
	id := uint16(packetID.Add(1))
	var result [][]byte
	for offset := 0; offset < len(transport); offset += 1480 {
		length := min(1480, len(transport)-offset)
		packet := make([]byte, 20+length)
		ip := header.IPv4(packet)
		flags := uint8(0); if offset+length < len(transport) { flags = header.IPv4FlagMoreFragments }
		ip.Encode(&header.IPv4Fields{TotalLength:uint16(len(packet)), ID:id, Flags:flags, FragmentOffset:uint16(offset), TTL:64, Protocol:17, SrcAddr:source, DstAddr:destination})
		binary.BigEndian.PutUint16(packet[10:12], ^checksum.Checksum(packet[:20], 0))
		copy(packet[20:], transport[offset:offset+length]); result = append(result, packet)
	}
	return result
}
