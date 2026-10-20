//go:build windows

package winengine

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"golang.org/x/sys/windows"
)

var _ platform.ReadyUDP = (*udpSocket)(nil)

// Watch transfers the Go descriptor to native, nonblocking datagram I/O.
// Shared workers own scheduling, packetization and byte-budget policy.
func (s *udpSocket) Watch(wake func()) (platform.Readiness, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.watch != nil {
		return nil, net.ErrClosed
	}
	if s.pool == nil {
		return nil, errors.New("UDP readiness service is not initialized")
	}
	file, err := s.conn.File()
	if err != nil {
		return nil, err
	}
	defer file.Close()
	h, err := duplicateForReadiness(file)
	if err != nil {
		return nil, err
	}
	watch, err := s.pool.watch(h, wake)
	if err != nil {
		windows.Closesocket(h)
		return nil, err
	}
	s.handle, s.watch = h, watch
	err = s.conn.Close()
	s.conn, s.raw = nil, nil
	if err != nil {
		return nil, err // Close still owns the installed watch and native handle.
	}
	return watch, nil
}

func (s *udpSocket) TryReadFrom(b []byte) (int, netip.AddrPort, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.watch == nil {
		return 0, netip.AddrPort{}, net.ErrClosed
	}
	buf := windows.WSABuf{Len: uint32(len(b))}
	if len(b) != 0 {
		buf.Buf = &b[0]
	}
	var source windows.RawSockaddrAny
	sourceLength := int32(unsafe.Sizeof(source))
	var received, flags uint32
	// NULL overlapped/completion routine selects documented synchronous usage.
	// FIONBIO on the descriptor makes that usage nonblocking.
	err := windows.WSARecvFrom(s.handle, &buf, 1, &received, &flags, &source, &sourceLength, nil, nil)
	runtime.KeepAlive(b)
	if errors.Is(err, windows.WSAEWOULDBLOCK) {
		return 0, netip.AddrPort{}, platform.ErrWouldBlock
	}
	if platform.IsTooBig(err) {
		return int(received), netip.AddrPort{}, &platform.TooBig{MTU: s.mtu}
	}
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	sa, err := source.Sockaddr()
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	switch a := sa.(type) {
	case *windows.SockaddrInet4:
		return int(received), netip.AddrPortFrom(netip.AddrFrom4(a.Addr), uint16(a.Port)), nil
	case *windows.SockaddrInet6:
		address := netip.AddrFrom16(a.Addr)
		if a.ZoneId != 0 {
			address = address.WithZone(strconv.FormatUint(uint64(a.ZoneId), 10))
		}
		return int(received), netip.AddrPortFrom(address, uint16(a.Port)), nil
	default:
		return 0, netip.AddrPort{}, fmt.Errorf("unexpected UDP address family %T", sa)
	}
}

func (s *udpSocket) TryWriteTo(b []byte, destination netip.AddrPort, df bool) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.watch == nil {
		return 0, net.ErrClosed
	}
	if !destination.IsValid() {
		return 0, errors.New("invalid UDP destination")
	}
	if err := s.fragmentation(s.handle, df); err != nil {
		return 0, err
	}
	var to windows.Sockaddr
	if destination.Addr().Is4() {
		to = &windows.SockaddrInet4{Addr: destination.Addr().As4(), Port: int(destination.Port())}
	} else {
		a := &windows.SockaddrInet6{Addr: destination.Addr().As16(), Port: int(destination.Port())}
		if zone := destination.Addr().Zone(); zone != "" {
			id, err := strconv.ParseUint(zone, 10, 32)
			if err != nil {
				return 0, fmt.Errorf("UDP destination requires a numeric scope: %w", err)
			}
			a.ZoneId = uint32(id)
		}
		to = a
	}
	buf := windows.WSABuf{Len: uint32(len(b))}
	if len(b) != 0 {
		buf.Buf = &b[0]
	}
	var sent uint32
	err := windows.WSASendto(s.handle, &buf, 1, &sent, 0, to, nil, nil)
	runtime.KeepAlive(b)
	if errors.Is(err, windows.WSAEWOULDBLOCK) {
		return 0, platform.ErrWouldBlock
	}
	if platform.IsTooBig(err) {
		return 0, &platform.TooBig{MTU: s.pathMTU(destination.Addr())}
	}
	return int(sent), err
}
