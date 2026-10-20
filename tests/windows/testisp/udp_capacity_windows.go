//go:build windows

package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// This peer lives on TestISP itself. It does not allocate another Windows
// socket per mapping, which would change the OS port limit being measured.
type udpCapacityResponder struct {
	mu        sync.Mutex
	active    bool
	seen      map[string]string
	packets   uint64
	replies   uint64
	dropped   uint64
	conflicts uint64
}

func (g *gateway) installUDPCapacity(mux *http.ServeMux) {
	mux.HandleFunc("POST /udp-capacity", func(w http.ResponseWriter, r *http.Request) {
		c := &g.udpCapacity
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.active {
			http.Error(w, "UDP capacity responder already active", 409)
			return
		}
		c.active, c.seen = true, make(map[string]string)
		c.packets, c.replies, c.dropped, c.conflicts = 0, 0, 0, 0
		json.NewEncoder(w).Encode(map[string]any{"host": "198.19.128.2", "host6": "2001:db8:198::2", "port": 26000})
	})
	mux.HandleFunc("GET /udp-capacity", func(w http.ResponseWriter, r *http.Request) {
		c := &g.udpCapacity
		c.mu.Lock()
		defer c.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"seen": c.seen, "packets": c.packets,
			"replies": c.replies, "dropped": c.dropped, "conflicts": c.conflicts})
	})
	mux.HandleFunc("POST /udp-capacity-close", func(w http.ResponseWriter, r *http.Request) {
		c := &g.udpCapacity
		c.mu.Lock()
		c.active = false
		c.mu.Unlock()
		w.Write([]byte("{}"))
	})
}

func (g *gateway) capacityUDP(id stack.TransportEndpointID, packet *stack.PacketBuffer, link *channel.Endpoint) bool {
	if id.LocalPort != 26000 || (id.LocalAddress != tcpip.AddrFrom4([4]byte{198, 19, 128, 2}) &&
		id.LocalAddress.String() != "2001:db8:198::2") {
		return false
	}
	c := &g.udpCapacity
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.active {
		return false
	}
	data := packet.Data().AsRange().ToSlice()
	if len(data) < 16 || string(data[:8]) != "NSUDPCAP" {
		c.dropped++
		return true
	}
	token := hex.EncodeToString(data[8:16])
	source := id.RemoteAddress.String() + ":" + portString(id.RemotePort)
	if previous, ok := c.seen[token]; ok && previous != source {
		c.conflicts++
	}
	if len(c.seen) >= 65536 {
		c.dropped++
		return true
	}
	c.seen[token] = source
	c.packets++
	payload := data
	if len(data) == 18 {
		size := int(binary.BigEndian.Uint16(data[16:]))
		maximum := 65507
		if id.LocalAddress.Len() == 16 {
			maximum = 65527
		}
		if size < 16 || size > maximum {
			c.dropped++
			return true
		}
		payload = make([]byte, size)
		for i := range payload {
			payload[i] = byte(i*37+11) ^ data[8+i%8]
		}
	}
	ok := true
	for _, wire := range udpReplies(id.LocalAddress, id.RemoteAddress, id.LocalPort, id.RemotePort, payload) {
		reply := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(wire)})
		var batch stack.PacketBufferList
		batch.PushBack(reply)
		if n, _ := link.WritePackets(batch); n != 1 {
			c.dropped++
			ok = false
		}
		reply.DecRef()
	}
	if ok {
		c.replies++
	}
	return true
}
