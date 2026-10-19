//go:build linux

package linux

import (
	"net"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

type diagSocket struct {
	file   *os.File
	fd     int
	buffer [4096]byte
}

// An Owners instance belongs to one network namespace. Its idle diagnostic
// sockets stay there, have no multicast subscriptions and serve one request
// at a time. The pool never shares a socket between concurrent lookups.
type diagPool struct {
	mu     sync.Mutex
	idle   []*diagSocket
	closed bool
}

func (p *diagPool) get() (*diagSocket, error) {
	if p != nil {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, net.ErrClosed
		}
		if n := len(p.idle); n > 0 {
			c := p.idle[n-1]
			p.idle = p.idle[:n-1]
			p.mu.Unlock()
			return c, nil
		}
		p.mu.Unlock()
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &diagSocket{fd: fd, file: os.NewFile(uintptr(fd), "sock_diag")}, nil
}

func (p *diagPool) put(c *diagSocket) {
	if p != nil {
		p.mu.Lock()
		if !p.closed && len(p.idle) < 32 {
			p.idle = append(p.idle, c)
			p.mu.Unlock()
			return
		}
		p.mu.Unlock()
	}
	c.file.Close()
}

func (p *diagPool) close() {
	p.mu.Lock()
	p.closed = true
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()
	for _, c := range idle {
		c.file.Close()
	}
}
