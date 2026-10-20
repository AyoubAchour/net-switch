//go:build linux

package linux

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var errReadinessOwned = errors.New("TCP blocking I/O is unavailable after readiness ownership transfer")

type tcpSocket struct {
	*net.TCPConn
	raw            syscall.RawConn
	mu             sync.Mutex
	fd             int
	native, closed bool
	local, remote  netip.AddrPort
}

// Dialing and probes use Go's ordinary TCP connection. Once the relay takes
// ownership, keep only a nonblocking fd and give Go's poll descriptor back.
// Otherwise every idle socket remains registered in two epoll instances and
// retains Go's netFD graph despite the relay having no blocking operations.
func (s *tcpSocket) takeReadiness() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if s.native {
		return errors.New("TCP socket already has a readiness owner")
	}
	fd := -1
	var duplicateErr error
	err := s.raw.Control(func(original uintptr) { fd, duplicateErr = unix.FcntlInt(original, unix.F_DUPFD_CLOEXEC, 0) })
	if err = errors.Join(err, duplicateErr); err != nil {
		if fd >= 0 {
			unix.Close(fd)
		}
		return err
	}
	// dup shares O_NONBLOCK with the connected file description; do not use
	// TCPConn.File, which changes the descriptor's blocking behavior.
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_NONBLOCK == 0 {
		unix.Close(fd)
		return errors.New("connected TCP descriptor is not nonblocking")
	}
	s.local = s.TCPConn.LocalAddr().(*net.TCPAddr).AddrPort()
	s.remote = s.TCPConn.RemoteAddr().(*net.TCPAddr).AddrPort()
	old := s.TCPConn
	s.TCPConn, s.raw = nil, nil
	s.fd, s.native = fd, true
	// The duplicate keeps the TCP connection alive; this only releases Go's
	// descriptor and its poll registration. No reconnect or unbound retry.
	return old.Close()
}

func (s *tcpSocket) control(fn func(uintptr)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if s.native {
		fn(uintptr(s.fd))
		return nil
	}
	return s.raw.Control(fn)
}

func (s *tcpSocket) legacy() (*net.TCPConn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, net.ErrClosed
	}
	if s.native {
		return nil, errReadinessOwned
	}
	return s.TCPConn, nil
}

func (s *tcpSocket) Read(b []byte) (int, error) {
	c, err := s.legacy()
	if err != nil {
		return 0, err
	}
	return c.Read(b)
}
func (s *tcpSocket) Write(b []byte) (int, error) {
	c, err := s.legacy()
	if err != nil {
		return 0, err
	}
	return c.Write(b)
}
func (s *tcpSocket) SetDeadline(t time.Time) error {
	c, err := s.legacy()
	if err != nil {
		return err
	}
	return c.SetDeadline(t)
}
func (s *tcpSocket) SetReadDeadline(t time.Time) error {
	c, err := s.legacy()
	if err != nil {
		return err
	}
	return c.SetReadDeadline(t)
}
func (s *tcpSocket) SetWriteDeadline(t time.Time) error {
	c, err := s.legacy()
	if err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (s *tcpSocket) LocalAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.native {
		return net.TCPAddrFromAddrPort(s.local)
	}
	return s.TCPConn.LocalAddr()
}
func (s *tcpSocket) RemoteAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.native {
		return net.TCPAddrFromAddrPort(s.remote)
	}
	return s.TCPConn.RemoteAddr()
}
func (s *tcpSocket) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	s.closed = true
	if s.native {
		return unix.Close(s.fd)
	}
	return s.TCPConn.Close()
}
func (s *tcpSocket) shutdown(how int) error {
	var shutdownErr error
	err := s.control(func(fd uintptr) { shutdownErr = unix.Shutdown(int(fd), how) })
	if err != nil {
		return err
	}
	return shutdownErr
}
func (s *tcpSocket) CloseRead() error  { return s.shutdown(unix.SHUT_RD) }
func (s *tcpSocket) CloseWrite() error { return s.shutdown(unix.SHUT_WR) }
func (s *tcpSocket) SetLinger(seconds int) error {
	var option unix.Linger
	if seconds >= 0 {
		option.Onoff, option.Linger = 1, int32(seconds)
	}
	var optionErr error
	err := s.control(func(fd uintptr) { optionErr = unix.SetsockoptLinger(int(fd), unix.SOL_SOCKET, unix.SO_LINGER, &option) })
	if err != nil {
		return err
	}
	return optionErr
}

func (s *tcpSocket) WaitReadable(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	raw, native, closed := s.raw, s.native, s.closed
	s.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	if native {
		return errReadinessOwned
	}
	var readErr error
	var peek [1]byte
	err := raw.Read(func(fd uintptr) bool {
		_, _, readErr = unix.Recvfrom(int(fd), peek[:], unix.MSG_PEEK|unix.MSG_DONTWAIT)
		return readErr != unix.EAGAIN && readErr != unix.EWOULDBLOCK
	})
	if err != nil {
		return err
	}
	return readErr
}
