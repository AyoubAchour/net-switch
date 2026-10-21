//go:build windows

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// Control's health probes (1.1.1.1, 8.8.8.8 and 9.9.9.9 on 443) reach the real
// internet through TestISP's relay, and they verify real certificates, so they
// cannot be answered by a local stand-in. A real ISP router relays them from
// its own port space. TestISP runs on the test PC, so at the port limit its
// relay competed for the PC's exhausted pool, refused the probes, and Control
// correctly took the line down (x64 capacity run 39662925396). For the
// capacity case only, TestISP reserves upstream ports before the pool fills
// and relays the probe targets from those: the router's own port space.
var probeTargets = map[string]bool{"1.1.1.1:443": true, "8.8.8.8:443": true, "9.9.9.9:443": true}

// Generous for a capacity run: Control probes a line a few connections at a
// time, and each relayed probe holds its port through TIME_WAIT.
const reservedProbePorts = 192

type probePorts struct {
	mu       sync.Mutex
	free     []windows.Handle // bound to the uplink address, not connected
	reserved int
	relayed  map[string]uint64
	shared   uint64 // probe connections that found the reservation empty
	errors   []string
	closed   bool
}

func reserveProbePorts(index int, source net.IP) (*probePorts, error) {
	p := &probePorts{relayed: map[string]uint64{}}
	for range reservedProbePorts {
		h, err := boundProbeSocket(index, source)
		if err != nil {
			p.close()
			return nil, fmt.Errorf("reserve probe relay port %d of %d: %w", p.reserved+1, reservedProbePorts, err)
		}
		p.free = append(p.free, h)
		p.reserved++
	}
	return p, nil
}

func boundProbeSocket(index int, source net.IP) (windows.Handle, error) {
	h, err := windows.Socket(windows.AF_INET, windows.SOCK_STREAM, windows.IPPROTO_TCP)
	if err != nil {
		return windows.InvalidHandle, err
	}
	// Same interface binding as the relay's ordinary dialer.
	var bytes [4]byte
	binary.BigEndian.PutUint32(bytes[:], uint32(index))
	if err := windows.SetsockoptInt(h, windows.IPPROTO_IP, 31, int(binary.LittleEndian.Uint32(bytes[:]))); err != nil {
		windows.Closesocket(h)
		return windows.InvalidHandle, err
	}
	address := &windows.SockaddrInet4{}
	copy(address.Addr[:], source.To4())
	if err := windows.Bind(h, address); err != nil {
		windows.Closesocket(h)
		return windows.InvalidHandle, err
	}
	return h, nil
}

// dial connects one reserved socket to a probe target. ok is false when the
// reservation is empty; the caller then uses the shared pool and it is counted.
func (p *probePorts) dial(ctx context.Context, destination string) (net.Conn, bool, error) {
	target, err := net.ResolveTCPAddr("tcp4", destination)
	if err != nil {
		return nil, true, err
	}
	p.mu.Lock()
	if p.closed || len(p.free) == 0 {
		p.shared++
		p.mu.Unlock()
		return nil, false, nil
	}
	h := p.free[len(p.free)-1]
	p.free = p.free[:len(p.free)-1]
	p.relayed[destination]++
	p.mu.Unlock()
	address := &windows.SockaddrInet4{Port: target.Port}
	copy(address.Addr[:], target.IP.To4())
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	connected := make(chan error, 1)
	go func() { connected <- windows.Connect(h, address) }()
	select {
	case err = <-connected:
	case <-ctx.Done():
		windows.Closesocket(h) // ends the blocking connect
		<-connected
		p.note(fmt.Errorf("reserved relay to %s: %w", destination, ctx.Err()))
		return nil, true, ctx.Err()
	}
	if err != nil {
		windows.Closesocket(h)
		p.note(fmt.Errorf("reserved relay to %s: %w", destination, err))
		return nil, true, err
	}
	// Test harness only: FileConn takes its own copy; the original is closed.
	f := os.NewFile(uintptr(h), "reserved probe relay")
	conn, err := net.FileConn(f)
	f.Close()
	if err != nil {
		p.note(err)
		return nil, true, err
	}
	return conn, true, nil
}

func (p *probePorts) note(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.errors) < 16 {
		p.errors = append(p.errors, err.Error())
	}
}

func (p *probePorts) stats() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	relayed := make(map[string]uint64, len(p.relayed))
	for k, v := range p.relayed {
		relayed[k] = v
	}
	return map[string]any{"mode": "health probes relayed from TestISP's reserved upstream ports",
		"reserved": p.reserved, "unused": len(p.free), "relayed": relayed, "fromSharedPool": p.shared, "errors": p.errors}
}

func (p *probePorts) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for _, h := range p.free {
		windows.Closesocket(h)
	}
	p.free = nil
}
