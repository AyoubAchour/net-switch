//go:build windows

package winengine

import (
	"encoding/binary"
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
	if s.goOwner.IsZero() {
		var err error
		s.goOwner, err = ownGoDescriptor(s.conn, "UDP Go connection before transfer")
		if err != nil {
			return nil, err
		}
	}
	file, err := s.conn.File()
	if err != nil {
		return nil, err
	}
	fileOwner, err := ownGoDescriptor(file, "UDP File duplicate")
	if err != nil {
		file.Close()
		return nil, err
	}
	defer fileOwner.CloseGo("UDP File duplicate close", file.Close)
	h, err := duplicateForReadiness(file, fileOwner)
	if err != nil {
		return nil, err
	}
	watch, err := s.pool.watch(h, wake)
	if err != nil {
		h.SocketClose("UDP failed readiness registration")
		return nil, err
	}
	s.handle, s.watch = h, watch
	err = s.goOwner.CloseGo("UDP source Go connection close", s.conn.Close)
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
	// SOCKADDR_STORAGE is 128 bytes with eight-byte alignment. RawSockaddrAny
	// alone has only two-byte alignment in Go; do not let stack layout choose
	// the alignment of a native IPv4/IPv6 output buffer.
	var address [16]uint64
	source := (*windows.RawSockaddrAny)(unsafe.Pointer(&address[0]))
	sourceLength := int32(unsafe.Sizeof(address))
	var received, flags uint32
	// NULL overlapped/completion routine selects documented synchronous usage.
	// FIONBIO on the descriptor makes that usage nonblocking.
	err := windows.WSARecvFrom(s.handle.Handle("UDP nonblocking receive"), &buf, 1, &received, &flags, source, &sourceLength, nil, nil)
	runtime.KeepAlive(b)
	if errors.Is(err, windows.WSAEWOULDBLOCK) {
		return 0, netip.AddrPort{}, platform.ErrWouldBlock
	}
	if platform.IsTooBig(err) {
		return int(received), netip.AddrPort{}, &platform.TooBig{MTU: s.mtu}
	}
	if err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("UDP receive local=%s buffer=%d received=%d flags=%d address-length=%d address-mod8=%d buffer-mod8=%d family=%d: %w",
			s.local, len(b), received, flags, sourceLength, uintptr(unsafe.Pointer(source))&7,
			uintptr(unsafe.Pointer(buf.Buf))&7, source.Addr.Family, err)
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
	if err := s.fragmentation(s.handle.Handle("UDP fragmentation option"), df); err != nil {
		return 0, err
	}
	// Use a full sockaddr allocation. x/sys's WSASendto convenience wrapper
	// widens a 16-byte IPv4 allocation to RawSockaddrAny (116 bytes), which
	// checkptr correctly rejects. The direct syscall accepts the exact length.
	var address [16]uint64
	to := (*windows.RawSockaddrAny)(unsafe.Pointer(&address[0]))
	var length int32
	if destination.Addr().Is4() {
		a := (*windows.RawSockaddrInet4)(unsafe.Pointer(to))
		a.Family, a.Addr = windows.AF_INET, destination.Addr().As4()
		binary.BigEndian.PutUint16(unsafe.Slice((*byte)(unsafe.Pointer(&a.Port)), 2), destination.Port())
		length = int32(unsafe.Sizeof(*a))
	} else {
		a := (*windows.RawSockaddrInet6)(unsafe.Pointer(to))
		a.Family, a.Addr = windows.AF_INET6, destination.Addr().As16()
		binary.BigEndian.PutUint16(unsafe.Slice((*byte)(unsafe.Pointer(&a.Port)), 2), destination.Port())
		length = int32(unsafe.Sizeof(*a))
		if zone := destination.Addr().Zone(); zone != "" {
			id, err := strconv.ParseUint(zone, 10, 32)
			if err != nil {
				return 0, fmt.Errorf("UDP destination requires a numeric scope: %w", err)
			}
			a.Scope_id = uint32(id)
		}
	}
	buf := windows.WSABuf{Len: uint32(len(b))}
	if len(b) != 0 {
		buf.Buf = &b[0]
	}
	var sent uint32
	err := windows.WSASendTo(s.handle.Handle("UDP nonblocking send"), &buf, 1, &sent, 0, to, length, nil, nil)
	runtime.KeepAlive(b)
	if errors.Is(err, windows.WSAEWOULDBLOCK) {
		return 0, platform.ErrWouldBlock
	}
	if platform.IsTooBig(err) {
		return 0, &platform.TooBig{MTU: s.pathMTU(destination.Addr())}
	}
	return int(sent), err
}
