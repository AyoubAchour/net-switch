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
	closed           bool
	workers          sync.WaitGroup
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
				c.connections = append(c.connections, conn)
				c.mu.Unlock()
				c.workers.Go(func() {
					defer conn.Close()
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
		json.NewEncoder(w).Encode(map[string]int{"accepted": responder.accepted, "echoed": responder.echoed})
	})
	mux.HandleFunc("POST /capacity-close", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if responder != nil {
			responder.close()
			responder = nil
		}
		io.WriteString(w, "{}")
	})
	go func() {
		<-g.done
		mu.Lock()
		defer mu.Unlock()
		if responder != nil {
			responder.close()
			responder = nil
		}
	}()
}
