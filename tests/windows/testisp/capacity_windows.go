//go:build windows

package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// A real TCP responder on TestISP's stack, only enabled for the capacity case.
// Each peer echoes single bytes for liveness checks without ordinary two-hop
// relay buffers. The engine itself still uses real bound Windows TCP sockets.
type capacityResponder struct {
	mu               sync.Mutex
	listeners        []net.Listener
	connections      []net.Conn
	accepted, echoed int
	// live counts accepted connections whose engine side has not closed:
	// the peer's own count, independent of the engine and the clients.
	live    int
	closed  bool
	workers sync.WaitGroup
}

func (c *capacityResponder) open(s *stack.Stack) error {
	for port := uint16(25000); port < 25008; port++ {
		l, err := gonet.ListenTCP(s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{198, 19, 128, 2}), Port: port}, header.IPv4ProtocolNumber)
		if err != nil {
			c.close()
			return err
		}
		c.listeners = append(c.listeners, l)
		c.workers.Go(func() {
			for {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				c.mu.Lock()
				if c.closed {
					c.mu.Unlock()
					conn.Close()
					return
				}
				c.accepted++
				c.live++
				c.connections = append(c.connections, conn)
				c.mu.Unlock()
				c.workers.Go(func() {
					defer func() {
						conn.Close()
						c.mu.Lock()
						c.live--
						c.mu.Unlock()
					}()
					var value [1]byte
					first := true
					for {
						if _, err := io.ReadFull(conn, value[:]); err != nil {
							return
						}
						if _, err := conn.Write(value[:]); err != nil {
							return
						}
						if first {
							c.mu.Lock()
							c.echoed++
							c.mu.Unlock()
							first = false
						}
					}
				})
			}
		})
	}
	return nil
}

func (c *capacityResponder) close() {
	c.mu.Lock()
	c.closed = true
	connections := c.connections
	c.connections = nil
	c.mu.Unlock()
	for _, l := range c.listeners {
		l.Close()
	}
	for _, conn := range connections {
		conn.Close()
	}
	c.workers.Wait()
}

func (g *gateway) installCapacity(mux *http.ServeMux) {
	var mu sync.Mutex
	var responder *capacityResponder
	mux.HandleFunc("POST /capacity", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if responder != nil {
			http.Error(w, "capacity responder already active", 409)
			return
		}
		c := &capacityResponder{}
		if err := c.open(g.stack); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		// Reserved before any capacity fill, so the native baselines and the
		// engine run see the same pool without these ports.
		ports, err := reserveProbePorts(g.index, g.uplinkIP)
		if err != nil {
			c.close()
			http.Error(w, err.Error(), 500)
			return
		}
		g.probePorts.Store(ports)
		responder = c
		json.NewEncoder(w).Encode(map[string]any{"host": "198.19.128.2", "ports": []int{25000, 25001, 25002, 25003, 25004, 25005, 25006, 25007}})
	})
	mux.HandleFunc("GET /capacity", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if responder == nil {
			http.Error(w, "capacity responder is not active", 409)
			return
		}
		responder.mu.Lock()
		defer responder.mu.Unlock()
		reply := map[string]any{"accepted": responder.accepted, "echoed": responder.echoed, "live": responder.live}
		if ports := g.probePorts.Load(); ports != nil {
			reply["probeRelay"] = ports.stats()
		}
		json.NewEncoder(w).Encode(reply)
	})
	mux.HandleFunc("POST /capacity-close", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		reply := map[string]any{}
		if ports := g.probePorts.Swap(nil); ports != nil {
			reply["probeRelay"] = ports.stats()
			ports.close()
		}
		if responder != nil {
			responder.close()
			responder = nil
		}
		json.NewEncoder(w).Encode(reply)
	})
	go func() {
		<-g.done
		mu.Lock()
		defer mu.Unlock()
		if ports := g.probePorts.Swap(nil); ports != nil {
			ports.close()
		}
		if responder != nil {
			responder.close()
			responder = nil
		}
	}()
}
