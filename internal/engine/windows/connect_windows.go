//go:build windows

package winengine

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

// tcpDialTimeout bounds one outbound TCP connect, as the Go dialer did before.
const tcpDialTimeout = 10 * time.Second

// Each relay socket keeps what Go's dialer gave it before (and the old copies
// carried): no Nagle delay, and keep-alive with the first probe after 30 s
// idle, then every 15 s, 9 probes.
var tcpConnectedOptions = [...]struct {
	name           string
	level, opt, on int
}{
	{"TCP_NODELAY", windows.IPPROTO_TCP, windows.TCP_NODELAY, 1},
	{"SO_KEEPALIVE", windows.SOL_SOCKET, windows.SO_KEEPALIVE, 1},
	{"TCP_KEEPIDLE", windows.IPPROTO_TCP, windows.TCP_KEEPIDLE, 30},
	{"TCP_KEEPINTVL", windows.IPPROTO_TCP, windows.TCP_KEEPINTVL, 15},
	{"TCP_KEEPCNT", windows.IPPROTO_TCP, windows.TCP_KEEPCNT, 9},
}

// dial creates one outbound TCP socket natively, with one handle owned from
// birth: the line's interface and port-reuse options, a bind to the line's
// source, registration on this completion port, then ConnectEx and
// SO_UPDATE_CONNECT_CONTEXT (SYSTEM-DESIGN 5.1).
// https://learn.microsoft.com/windows/win32/api/mswsock/nc-mswsock-lpfn_connectex
func (p *readiness) dial(ctx context.Context, a Adapter, source netip.Addr, remote netip.AddrPort) (*readySocket, error) {
	v6 := remote.Addr().Is6()
	network := "tcp4"
	if v6 {
		network = "tcp6"
	}
	local := netip.AddrPortFrom(source, 0)
	fail := func(err error) error {
		return &net.OpError{Op: "dial", Net: network, Source: net.TCPAddrFromAddrPort(local), Addr: net.TCPAddrFromAddrPort(remote), Err: err}
	}
	ctx, cancel := context.WithTimeout(ctx, tcpDialTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, fail(err)
	}
	socket, err := newSocket(v6, windows.SOCK_STREAM, "TCP native socket open")
	if err != nil {
		return nil, fail(err)
	}
	connectEx, err := prepareTCP(socket, a, local, v6)
	if err != nil {
		return nil, fail(closeFailed(socket, "TCP native setup failure close", err))
	}
	w, err := p.register(socket)
	if err != nil {
		return nil, fail(closeFailed(socket, "TCP native registration failure close", err))
	}
	p.connects.Add(1)
	if err := w.connect(ctx, connectEx, remote); err != nil {
		// connect returns only after any packet drained; leave the port, then close.
		w.Detach()
		return nil, fail(closeFailed(socket, "TCP native connect failure close", err))
	}
	bound, peer, err := finishTCP(socket)
	if err != nil {
		w.Detach()
		return nil, fail(closeFailed(socket, "TCP native connected setup failure close", err))
	}
	if !peer.IsValid() {
		peer = remote
	}
	p.mu.Lock()
	w.localPort, w.remote, w.established = bound.Port(), net.TCPAddrFromAddrPort(peer).String(), true
	p.mu.Unlock()
	return &readySocket{handle: socket, pool: p, watch: w,
		local: net.TCPAddrFromAddrPort(bound), remote: net.TCPAddrFromAddrPort(peer)}, nil
}

// prepareTCP applies the socket options of the old Go dial path in its order,
// binds to the line's source and looks up ConnectEx for this socket's provider.
func prepareTCP(socket winhandle.Owner, a Adapter, local netip.AddrPort, v6 bool) (uintptr, error) {
	h := socket.Handle("TCP native socket setup")
	if err := setFamilyDefaults(h, v6, false); err != nil {
		return 0, err
	}
	if err := setLineInterface(h, a, v6); err != nil {
		return 0, err
	}
	// ConnectEx requires an explicit source bind. Let Windows reuse ephemeral
	// ports when its existing auto-reuse configuration permits it; never
	// change that machine-wide configuration.
	if err := windows.SetsockoptInt(h, windows.SOL_SOCKET, soReuseUnicastPort, 1); err != nil {
		return 0, os.NewSyscallError("setsockopt SO_REUSE_UNICASTPORT", err)
	}
	if err := bindSource(h, local); err != nil {
		return 0, err
	}
	// Extension pointers belong to the socket's provider, so each socket asks
	// its own. This ioctl is synchronous and runs before port association.
	guid := windows.WSAID_CONNECTEX
	var connectEx uintptr
	var returned uint32
	if err := windows.WSAIoctl(h, windows.SIO_GET_EXTENSION_FUNCTION_POINTER,
		(*byte)(unsafe.Pointer(&guid)), uint32(unsafe.Sizeof(guid)),
		(*byte)(unsafe.Pointer(&connectEx)), uint32(unsafe.Sizeof(connectEx)), &returned, nil, 0); err != nil {
		return 0, os.NewSyscallError("WSAIoctl ConnectEx", err)
	}
	if connectEx == 0 || returned != uint32(unsafe.Sizeof(connectEx)) {
		return 0, fmt.Errorf("WSAIoctl returned ConnectEx %#x in %d bytes", connectEx, returned)
	}
	return connectEx, nil
}

// connect runs ConnectEx on a registered socket and returns its Winsock
// result. op, the destination and the byte count live in w, which stays pinned
// and registered until Detach. Cancellation follows the readiness rule:
// CancelIoEx, then the completion packet, and only then may the caller release
// op or close the socket.
func (w *socketWatch) connect(ctx context.Context, connectEx uintptr, remote netip.AddrPort) error {
	length, err := w.setDestination(remote)
	if err != nil {
		return err
	}
	h := w.socket.Handle("TCP ConnectEx")
	w.mu.Lock()
	w.op = windows.Overlapped{}
	w.connecting, w.pending = true, true
	// Every pointer is converted inside the call's own argument list.
	r, _, callErr := syscall.SyscallN(connectEx, uintptr(h), uintptr(unsafe.Pointer(&w.name[0])), uintptr(length),
		0, 0, uintptr(unsafe.Pointer(&w.sent)), uintptr(unsafe.Pointer(&w.op)))
	err = nil
	if r == 0 {
		err = callErr
		if callErr == 0 {
			err = syscall.EINVAL
		}
	}
	wait := false
	switch {
	case errors.Is(err, windows.ERROR_IO_PENDING):
		w.pool.pendingConn.Add(1)
		err, wait = nil, true
	case err == nil && !w.skipSuccess:
		// Synchronous success still queues its packet, which owns op.
		wait = true
	default:
		// An immediate failure, or immediate success with skip-on-success,
		// queues no packet.
		w.connecting, w.pending = false, false
	}
	w.mu.Unlock()
	if !wait {
		if err != nil {
			return os.NewSyscallError("connectex", err)
		}
		return nil
	}
	cancelled := false
	select {
	case <-w.connected:
	case <-ctx.Done():
		if err := w.pool.cancel(h, &w.op); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
			// As in Detach: returning would let the caller close the socket
			// and free op while the kernel still owns it. Fatal, not recovered.
			panic(fmt.Errorf("TCP ConnectEx CancelIoEx handle=%#x key=%d skipSuccess=%t: %w", h, w.key, w.skipSuccess, err))
		}
		// ERROR_NOT_FOUND means the connect finished first; its packet
		// still has to arrive before op is released.
		<-w.connected
		cancelled = true
	}
	var sent, flags uint32
	// The packet carries an NTSTATUS; this reads it back as a Winsock error,
	// so port exhaustion stays WSAENOBUFS/WSAEADDRINUSE for the diagnostics.
	result := windows.WSAGetOverlappedResult(h, &w.op, &sent, false, &flags)
	if cancelled {
		// A connect that won the race is still abandoned: its caller is gone.
		return ctx.Err()
	}
	if result != nil {
		return os.NewSyscallError("connectex", result)
	}
	return nil
}

// setDestination writes the peer into w's aligned SOCKADDR_STORAGE.
func (w *socketWatch) setDestination(remote netip.AddrPort) (int32, error) {
	w.name = [16]uint64{}
	if remote.Addr().Is4() {
		a := (*windows.RawSockaddrInet4)(unsafe.Pointer(&w.name[0]))
		a.Family, a.Addr = windows.AF_INET, remote.Addr().As4()
		binary.BigEndian.PutUint16(unsafe.Slice((*byte)(unsafe.Pointer(&a.Port)), 2), remote.Port())
		return int32(unsafe.Sizeof(*a)), nil
	}
	a := (*windows.RawSockaddrInet6)(unsafe.Pointer(&w.name[0]))
	a.Family, a.Addr = windows.AF_INET6, remote.Addr().As16()
	binary.BigEndian.PutUint16(unsafe.Slice((*byte)(unsafe.Pointer(&a.Port)), 2), remote.Port())
	if zone := remote.Addr().Zone(); zone != "" {
		id, err := strconv.ParseUint(zone, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("TCP destination requires a numeric scope: %w", err)
		}
		a.Scope_id = uint32(id)
	}
	return int32(unsafe.Sizeof(*a)), nil
}

// finishTCP makes a socket ConnectEx connected usable: until
// SO_UPDATE_CONNECT_CONTEXT it is in the default connected state, without its
// earlier options or a usable name, and shutdown would fail.
func finishTCP(socket winhandle.Owner) (netip.AddrPort, netip.AddrPort, error) {
	h := socket.Handle("TCP connected setup")
	if err := windows.Setsockopt(h, windows.SOL_SOCKET, windows.SO_UPDATE_CONNECT_CONTEXT, nil, 0); err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, os.NewSyscallError("setsockopt SO_UPDATE_CONNECT_CONTEXT", err)
	}
	for _, option := range tcpConnectedOptions {
		if err := windows.SetsockoptInt(h, option.level, option.opt, option.on); err != nil {
			return netip.AddrPort{}, netip.AddrPort{}, os.NewSyscallError("setsockopt "+option.name, err)
		}
	}
	if err := setNonblocking(socket, "TCP connected nonblocking"); err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, err
	}
	bound, err := localName(h)
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, err
	}
	var peer netip.AddrPort
	if sa, err := windows.Getpeername(h); err == nil {
		peer, _ = addrPort(sa)
	}
	return bound, peer, nil
}
