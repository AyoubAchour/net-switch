//go:build linux

package linux

import (
	"errors"
	"net"
	"net/netip"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"golang.org/x/sys/unix"
)

func (s *udpSocket) Watch(wake func()) (platform.Readiness, error) {
	p, err := tcpPoller()
	if err != nil {
		return nil, err
	}
	// RawConn.Control pins the nonblocking fd against concurrent Close. No
	// RawConn.Read/Write: those would park the shared worker in Go's poller.
	w := p.watch(s.raw.Control, wake)
	w.errorReady = func() { s.errorReady.Store(true) }
	return w, nil
}

func (s *udpSocket) TryReadFrom(b []byte) (int, netip.AddrPort, error) {
	var n, flags int
	var from unix.Sockaddr
	var readErr error
	err := s.raw.Control(func(fd uintptr) {
		for {
			n, _, flags, from, readErr = unix.Recvmsg(int(fd), b, nil, unix.MSG_DONTWAIT)
			if readErr != unix.EINTR {
				break
			}
		}
	})
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	if readErr == unix.EAGAIN {
		// EPOLLERR remains level-ready while error-queue entries remain,
		// even after the ordinary socket error has been consumed.
		if s.errorReady.Swap(false) {
			s.drainErrors()
		}
		return 0, netip.AddrPort{}, platform.ErrWouldBlock
	}
	if readErr != nil {
		if !errors.Is(readErr, net.ErrClosed) {
			s.drainErrors()
		}
		return 0, netip.AddrPort{}, readErr
	}
	if flags&unix.MSG_TRUNC != 0 {
		return 0, netip.AddrPort{}, &platform.TooBig{}
	}
	switch a := from.(type) {
	case *unix.SockaddrInet4:
		return n, netip.AddrPortFrom(netip.AddrFrom4(a.Addr), uint16(a.Port)), nil
	case *unix.SockaddrInet6:
		return n, netip.AddrPortFrom(netip.AddrFrom16(a.Addr), uint16(a.Port)), nil
	default:
		return 0, netip.AddrPort{}, errors.New("UDP reply has no IP source")
	}
}

func (s *udpSocket) TryWriteTo(b []byte, dst netip.AddrPort, df bool) (int, error) {
	if !dst.IsValid() || dst.Addr().Is6() != s.v6 {
		return 0, unix.EAFNOSUPPORT
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	var sendErr error
	err := s.raw.Control(func(fd uintptr) {
		mode := unix.IP_PMTUDISC_DONT
		if df {
			mode = unix.IP_PMTUDISC_DO
		}
		var to unix.Sockaddr
		if s.v6 {
			sendErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, mode)
			to = &unix.SockaddrInet6{Addr: dst.Addr().As16(), Port: int(dst.Port())}
		} else {
			sendErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, mode)
			to = &unix.SockaddrInet4{Addr: dst.Addr().As4(), Port: int(dst.Port())}
		}
		if sendErr != nil {
			return
		}
		sendErr = s.sendAttributed(dst, len(b), func() error {
			for {
				err := unix.Sendto(int(fd), b, unix.MSG_DONTWAIT, to)
				if err != unix.EINTR {
					return err
				}
			}
		})
	})
	if err != nil {
		return 0, err
	}
	switch sendErr {
	case nil:
		return len(b), nil
	case unix.EAGAIN:
		return 0, platform.ErrWouldBlock
	default:
		return 0, sendErr
	}
}
