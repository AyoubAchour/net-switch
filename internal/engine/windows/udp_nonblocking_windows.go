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

// Watch hands the socket's only handle to the shared event-select readiness.
// Nothing is copied: the engine created this socket natively and owns it.
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
	watch, err := s.pool.watch(s.handle, wake)
	if err != nil {
		return nil, fmt.Errorf("UDP readiness event registration: %w", err)
	}
	s.watch = watch
	return watch, nil
}

func (s *udpSocket) TryReadFrom(b []byte) (int, netip.AddrPort, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.watch == nil {
		return 0, netip.AddrPort{}, net.ErrClosed
	}
	return s.receive(b, "UDP nonblocking receive")
}

// receive is one synchronous nonblocking WSARecvFrom; the caller holds s.mu.
func (s *udpSocket) receive(b []byte, site string) (int, netip.AddrPort, error) {
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
	err := windows.WSARecvFrom(s.handle.Handle(site), &buf, 1, &received, &flags, source, &sourceLength, nil, nil)
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
	from, ok := addrPort(sa)
	if !ok {
		return 0, netip.AddrPort{}, fmt.Errorf("unexpected UDP address family %T", sa)
	}
	return int(received), from, nil
}

func (s *udpSocket) TryWriteTo(b []byte, destination netip.AddrPort, df bool) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.watch == nil {
		return 0, net.ErrClosed
	}
	return s.send(b, destination, df, "nonblocking send")
}

// send is one synchronous nonblocking WSASendTo; the caller holds s.mu. stage
// names the caller in the send-failure diagnostics.
func (s *udpSocket) send(b []byte, destination netip.AddrPort, df bool, stage string) (int, error) {
	if !destination.IsValid() {
		return 0, errors.New("invalid UDP destination")
	}
	if err := s.fragmentation(s.handle.Handle("UDP fragmentation option"), df); err != nil {
		noteUDPSendFailure(stage+" fragmentation option", destination, err)
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
	if errors.Is(err, windows.WSAENOBUFS) {
		return int(sent), platform.ErrDatagramDropped
	}
	if platform.IsTooBig(err) {
		return 0, &platform.TooBig{MTU: s.pathMTU(destination.Addr())}
	}
	noteUDPSendFailure(stage, destination, err)
	return int(sent), err
}
