//go:build windows

package winengine

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

// Outbound sockets are created natively, with one handle owned from birth
// (SYSTEM-DESIGN 5.1, a coordinator decision of 2026-10-21). Go's network
// package never sees them, so nothing has to be taken back from it: no File()
// copy and no second Winsock duplicate. Microsoft documents that a socket
// descriptor is valid in every thread of the process that created it.
// https://learn.microsoft.com/windows/win32/api/winsock2/nf-winsock2-wsaduplicatesocketw

const (
	ipUnicastIf        = 31     // IP_UNICAST_IF and IPV6_UNICAST_IF.
	soReuseUnicastPort = 0x3007 // SO_REUSE_UNICASTPORT.
	soProtocolInfoW    = 0x2005 // SO_PROTOCOL_INFOW.
	fionbio            = 0x8004667e
	pollRdNorm         = 0x100
	pollWrNorm         = 0x10
)

var ioctlsocketProc = winsock.NewProc("ioctlsocket")

// setLineInterface pins a socket's egress to the line's interface. IPv4 takes
// the index in network byte order, IPv6 in host order.
// https://learn.microsoft.com/windows/win32/winsock/ipproto-ip-socket-options
func setLineInterface(h windows.Handle, a Adapter, v6 bool) error {
	level, index := windows.IPPROTO_IP, a.Index4
	if v6 {
		level, index = windows.IPPROTO_IPV6, a.Index6
	} else {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], index)
		index = binary.LittleEndian.Uint32(b[:])
	}
	if err := windows.SetsockoptInt(h, level, ipUnicastIf, int(index)); err != nil {
		return os.NewSyscallError("setsockopt IP_UNICAST_IF", err)
	}
	return nil
}

// newSocket creates an overlapped, non-inheritable socket and records its only
// owner before any other call can see the value.
//
// The protocol is 0, Winsock's default for the type, exactly as Go's network
// package created these sockets before. Both 0 and IPPROTO_UDP select the same
// catalog entry (MSAFD Tcpip [UDP/IP] on the hosted runners), yet with an
// explicit IPPROTO_UDP the real-TUN port-limit gate held 2,047 (ARM64) and
// 5,503 (x64) UDP flows instead of about 7,950: the apps' own connects were
// refused WSAENOBUFS with thousands of ports free. Protocol 0 held 7,936.
// The mechanism inside Winsock/AFD is not known; keep Go's exact call.
func newSocket(v6 bool, kind int32, site string) (winhandle.Owner, error) {
	family := int32(windows.AF_INET)
	if v6 {
		family = windows.AF_INET6
	}
	h, err := windows.WSASocket(family, kind, 0, nil, 0, windows.WSA_FLAG_OVERLAPPED|windows.WSA_FLAG_NO_HANDLE_INHERIT)
	if err != nil {
		return winhandle.Owner{}, os.NewSyscallError("socket", err)
	}
	return winhandle.Open(h, site), nil
}

// closeFailed closes a socket whose setup failed. The setup error keeps its
// own type (a timeout stays a timeout) unless the close fails too.
func closeFailed(socket winhandle.Owner, site string, err error) error {
	if closeErr := socket.SocketClose(site); closeErr != nil {
		return errors.Join(err, fmt.Errorf("close after failed setup: %w", closeErr))
	}
	return err
}

// setFamilyDefaults keeps the options Go's network package set on these
// sockets before: an IPv6 socket accepts IPv6 only, and IPv4 datagram sockets
// may broadcast.
func setFamilyDefaults(h windows.Handle, v6, datagram bool) error {
	if v6 {
		if err := windows.SetsockoptInt(h, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY, 1); err != nil {
			return os.NewSyscallError("setsockopt IPV6_V6ONLY", err)
		}
	} else if datagram {
		if err := windows.SetsockoptInt(h, windows.SOL_SOCKET, windows.SO_BROADCAST, 1); err != nil {
			return os.NewSyscallError("setsockopt SO_BROADCAST", err)
		}
	}
	return nil
}

func socketAddress(a netip.AddrPort) (windows.Sockaddr, error) {
	if a.Addr().Is4() {
		return &windows.SockaddrInet4{Port: int(a.Port()), Addr: a.Addr().As4()}, nil
	}
	sa := &windows.SockaddrInet6{Port: int(a.Port()), Addr: a.Addr().As16()}
	if zone := a.Addr().Zone(); zone != "" {
		id, err := strconv.ParseUint(zone, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("address %s requires a numeric scope: %w", a, err)
		}
		sa.ZoneId = uint32(id)
	}
	return sa, nil
}

func bindSource(h windows.Handle, local netip.AddrPort) error {
	sa, err := socketAddress(local)
	if err != nil {
		return err
	}
	if err := windows.Bind(h, sa); err != nil {
		return os.NewSyscallError("bind", err)
	}
	return nil
}

func addrPort(sa windows.Sockaddr) (netip.AddrPort, bool) {
	switch a := sa.(type) {
	case *windows.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(a.Addr), uint16(a.Port)), true
	case *windows.SockaddrInet6:
		address := netip.AddrFrom16(a.Addr)
		if a.ZoneId != 0 {
			address = address.WithZone(strconv.FormatUint(uint64(a.ZoneId), 10))
		}
		return netip.AddrPortFrom(address, uint16(a.Port)), true
	}
	return netip.AddrPort{}, false
}

func localName(h windows.Handle) (netip.AddrPort, error) {
	sa, err := windows.Getsockname(h)
	if err != nil {
		return netip.AddrPort{}, os.NewSyscallError("getsockname", err)
	}
	a, ok := addrPort(sa)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("getsockname returned %T", sa)
	}
	return a, nil
}

// setNonblocking selects documented synchronous nonblocking calls for the
// relay's recv/send and WSARecvFrom/WSASendTo. Overlapped calls are unaffected.
func setNonblocking(socket winhandle.Owner, site string) error {
	var on uint32 = 1
	code, _, err := ioctlsocketProc.Call(uintptr(socket.Handle(site)), fionbio, uintptr(unsafe.Pointer(&on)))
	if int32(code) != 0 {
		return os.NewSyscallError("ioctlsocket FIONBIO", err)
	}
	return nil
}

// socketProviderIFS reports whether the provider behind this socket returns
// IFS handles. SO_PROTOCOL_INFOW describes the socket's own (top) provider, so
// a non-IFS layered provider installed after startup is still seen here.
// https://learn.microsoft.com/windows/win32/winsock/sol-socket-socket-options
func socketProviderIFS(socket winhandle.Owner) (bool, error) {
	var info windows.WSAProtocolInfo
	size := int32(unsafe.Sizeof(info))
	if err := windows.Getsockopt(socket.Handle("TCP socket provider query"), windows.SOL_SOCKET, soProtocolInfoW,
		(*byte)(unsafe.Pointer(&info)), &size); err != nil {
		return false, os.NewSyscallError("getsockopt SO_PROTOCOL_INFOW", err)
	}
	return info.ServiceFlags1&windows.XP1_IFS_HANDLES != 0, nil
}
