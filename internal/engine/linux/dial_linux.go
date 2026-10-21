//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func bindSocket(raw syscall.RawConn, l lineState) error {
	var err error
	control := raw.Control(func(fd uintptr) {
		// Both must succeed before connect/send. There is no unbound retry.
		err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX, l.Index)
		if err == nil {
			err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(l.Mark))
		}
	})
	return errors.Join(control, err)
}
func (p *Platform) DialTCP(ctx context.Context, id string, dst netip.AddrPort) (platform.TCPConn, error) {
	l, err := p.binding(id, dst.Addr().Is6())
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Control: func(_, _ string, raw syscall.RawConn) error { return bindSocket(raw, l) }}
	c, err := d.DialContext(ctx, "tcp", dst.String())
	if err != nil {
		return nil, err
	}
	tcp := c.(*net.TCPConn)
	raw, err := tcp.SyscallConn()
	if err != nil {
		tcp.Close()
		return nil, err
	}
	return &tcpSocket{TCPConn: tcp, raw: raw}, nil
}

func (p *Platform) OpenUDP(ctx context.Context, id string, v6 bool) (platform.UDPConn, error) {
	// Compatibility for callers without a first destination. This is only a
	// route query; no packet is sent to this address.
	dst := netip.MustParseAddrPort("1.1.1.1:443")
	if v6 {
		dst = netip.MustParseAddrPort("[2606:4700:4700::1111]:443")
	}
	return p.OpenUDPTo(ctx, id, dst)
}

func (p *Platform) OpenUDPTo(ctx context.Context, id string, dst netip.AddrPort) (platform.UDPConn, error) {
	v6 := dst.Addr().Is6()
	l, err := p.binding(id, v6)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	routes, err := retryDump(ctx, func() ([]netlink.Route, error) {
		return netlink.RouteGetWithOptions(net.IP(dst.Addr().AsSlice()), &netlink.RouteGetOptions{OifIndex: l.Index, Mark: l.Mark})
	})
	if err != nil {
		return nil, err
	}
	var source netip.Addr
	for _, r := range routes {
		if r.LinkIndex == l.Index {
			if ip, ok := netip.AddrFromSlice(r.Src); ok && !ip.IsUnspecified() {
				source = ip.Unmap()
				break
			}
		}
	}
	if !source.IsValid() {
		return nil, fmt.Errorf("line %s has no usable source route to %s", id, dst)
	}
	family := "udp4"
	if v6 {
		family = "udp6"
	}
	address := net.JoinHostPort(source.String(), "0")
	lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		if err := bindSocket(raw, l); err != nil {
			return err
		}
		var err error
		e := raw.Control(func(fd uintptr) {
			if v6 {
				err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVERR, 1)
			} else {
				err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVERR, 1)
			}
		})
		return errors.Join(e, err)
	}}
	pc, err := lc.ListenPacket(ctx, family, address)
	if err != nil {
		return nil, err
	}
	c := pc.(*net.UDPConn)
	raw, err := c.SyscallConn()
	if err != nil {
		c.Close()
		return nil, err
	}
	routeLost := func() bool { _, err := p.binding(id, v6); return err != nil }
	return &udpSocket{conn: c, raw: raw, v6: v6, errors: make(chan platform.DatagramError, 1), done: make(chan struct{}), routeLost: routeLost, route: &p.udpRoute}, nil
}

type udpSocket struct {
	conn             *net.UDPConn
	raw              syscall.RawConn
	v6               bool
	writeMu, errorMu sync.Mutex
	once             sync.Once
	errors           chan platform.DatagramError
	done             chan struct{}
	handler          func(platform.DatagramError)
	errorReady       atomic.Bool
	// routeLost reports whether the socket's line binding has no usable
	// route now; route counts how its route errors were settled.
	routeLost func() bool
	route     *routeCounters
}

// routeCounters count UDP sends that failed again with a route error after
// the retry. Unreachable ones were returned because the line's binding had no
// usable route; dropped ones were unproven and counted silently.
type routeCounters struct {
	unreachable, dropped atomic.Uint64
}

// Stats reports the platform's UDP route-error outcomes.
func (p *Platform) Stats() any {
	return struct{ UDPRouteUnreachable, UDPRouteDropped uint64 }{p.udpRoute.unreachable.Load(), p.udpRoute.dropped.Load()}
}

// errRouteDropped is a route error the line's binding doesn't confirm. The
// shared UDP code counts it as an ordinary silent drop.
var errRouteDropped = fmt.Errorf("unconfirmed UDP route error: %w", platform.ErrDatagramDropped)

func (s *udpSocket) LocalAddr() netip.AddrPort { return s.conn.LocalAddr().(*net.UDPAddr).AddrPort() }
func (s *udpSocket) Close() error              { s.once.Do(func() { close(s.done) }); return s.conn.Close() }
func (s *udpSocket) SetErrorHandler(handler func(platform.DatagramError)) {
	s.errorMu.Lock()
	s.handler = handler
	s.errorMu.Unlock()
}
func (s *udpSocket) WaitReadable(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var readErr error
	var peek [1]byte
	err := s.raw.Read(func(fd uintptr) bool {
		_, _, readErr = unix.Recvfrom(int(fd), peek[:], unix.MSG_PEEK|unix.MSG_DONTWAIT)
		return readErr != unix.EAGAIN && readErr != unix.EWOULDBLOCK
	})
	err = errors.Join(err, readErr)
	if err != nil && !errors.Is(err, net.ErrClosed) {
		s.drainErrors()
	}
	return err
}
func (s *udpSocket) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	n, a, err := s.conn.ReadFromUDPAddrPort(b)
	if err != nil && !errors.Is(err, net.ErrClosed) {
		s.drainErrors()
	}
	return n, a, err
}
func (s *udpSocket) WriteTo(b []byte, dst netip.AddrPort, df bool) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	var err error
	e := s.raw.Control(func(fd uintptr) {
		mode := unix.IP_PMTUDISC_DONT
		if df {
			mode = unix.IP_PMTUDISC_DO
		}
		if s.v6 {
			err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, mode)
		} else {
			err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, mode)
		}
	})
	if err = errors.Join(e, err); err != nil {
		return 0, err
	}
	var n int
	err = s.sendAttributed(dst, len(b), func() error {
		var sendErr error
		n, sendErr = s.conn.WriteToUDPAddrPort(b, dst)
		return sendErr
	})
	return n, err
}

// sendAttributed runs send and decides whether a failure belongs to dst. It
// holds errorMu from the first error-queue pass through the retry, so no
// reader dequeue can re-arm the socket error in between. Notifications run
// after the lock is released.
func (s *udpSocket) sendAttributed(dst netip.AddrPort, size int, send func() error) error {
	var drain errorDrain
	locked := false
	err := sendDatagram(send, func(errno unix.Errno) errorEvidence {
		if !locked {
			s.errorMu.Lock()
			locked, drain.handler = true, s.handler
		}
		return s.drainLocked(&drain, errno, dst, size)
	}, s.clearSocketError, s.routeLost)
	if locked {
		s.errorMu.Unlock()
		drain.deliver()
	}
	if s.route != nil {
		if err == errRouteDropped {
			s.route.dropped.Add(1)
		} else if errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EHOSTUNREACH) {
			s.route.unreachable.Add(1)
		}
	}
	return err
}

// clearSocketError consumes the SO_ERROR latch. Dequeuing an ICMP report
// re-arms it from the next queued report; reports past the drain bound stay
// queued and keep EPOLLERR level-ready for the reader.
func (s *udpSocket) clearSocketError() {
	s.raw.Control(func(fd uintptr) { unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ERROR) })
}

// pathMTU replaces a missing MTU with the family's minimum.
func (s *udpSocket) pathMTU(mtu uint32) uint32 {
	if mtu != 0 {
		return mtu
	}
	if s.v6 {
		return 1280
	}
	return 576
}

// exceeds reports whether a payload of size bytes cannot fit mtu, using the
// header lengths Linux's local EMSGSIZE checks use for an option-free socket.
func (s *udpSocket) exceeds(size int, mtu uint32) bool {
	header := 28
	if s.v6 {
		header = 48
	}
	return mtu == 0 || size+header > int(mtu)
}

// A single socket reader drains the error queue when the kernel wakes it with
// SO_ERROR. A second RawConn.Read would compete for Go's read lock and could
// starve replies. ReadError consumes bounded messages from this channel.
func (s *udpSocket) drainErrors() {
	s.errorMu.Lock()
	drain := errorDrain{handler: s.handler}
	s.drainLocked(&drain, 0, netip.AddrPort{}, 0)
	s.errorMu.Unlock()
	drain.deliver()
}

// errorDrainLimit bounds one pass. A peer can keep the queue full, and one
// mapping must not monopolize the shared UDP worker; the rest stays queued.
const errorDrainLimit = 16

// errorEvidence is what one bounded error-queue pass showed about a send.
type errorEvidence struct {
	empty  bool   // the queue ran dry within the bound
	remote bool   // an ICMP report carried the errno being explained
	local  bool   // a local EMSGSIZE report covers the send being explained
	mtu    uint32 // that local report's path MTU
}

// errorDrain holds at most one handler notification until errorMu is released.
type errorDrain struct {
	handler func(platform.DatagramError)
	pending platform.DatagramError
	ready   bool
}

func (d *errorDrain) deliver() {
	if d.ready {
		d.handler(d.pending)
	}
}

// drainLocked consumes at most errorDrainLimit error-queue entries under
// errorMu. ICMP reports become notifications for the destination and payload
// they quote. When errno is non-zero it also gathers evidence about a failed
// send of size bytes to dst.
func (s *udpSocket) drainLocked(d *errorDrain, errno unix.Errno, dst netip.AddrPort, size int) errorEvidence {
	s.errorReady.Store(false)
	var evidence errorEvidence
	scratch := errorBuffers.Get().(*errorScratch)
	defer errorBuffers.Put(scratch)
	data, control := scratch.data[:], scratch.control[:]
	for i := 0; i < errorDrainLimit; i++ {
		var n, oob int
		var from unix.Sockaddr
		var err error
		e := s.raw.Control(func(fd uintptr) {
			n, oob, _, from, err = unix.Recvmsg(int(fd), data, control, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
		})
		if e == nil && err == unix.EAGAIN {
			evidence.empty = true
		}
		if e != nil || err != nil {
			break
		}
		var named netip.AddrPort
		switch a := from.(type) {
		case *unix.SockaddrInet4:
			named = netip.AddrPortFrom(netip.AddrFrom4(a.Addr), uint16(a.Port))
		case *unix.SockaddrInet6:
			named = netip.AddrPortFrom(netip.AddrFrom16(a.Addr), uint16(a.Port))
		}
		if !named.IsValid() {
			continue
		}
		messages, err := unix.ParseSocketControlMessage(control[:oob])
		if err != nil {
			continue
		}
		for _, m := range messages {
			if !((m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_RECVERR) || (m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_RECVERR)) || len(m.Data) < 16 {
				continue
			}
			// struct sock_extended_err: errno, origin, type, code, pad, info.
			reported := unix.Errno(binary.NativeEndian.Uint32(m.Data))
			info := binary.NativeEndian.Uint32(m.Data[8:])
			switch m.Data[4] {
			case unix.SO_EE_ORIGIN_LOCAL:
				// LOCAL errors belong to a synchronous send failure. Linux may
				// supply no UDP port or payload, so the sender quotes its own
				// packet instead of a second ICMP with a port-zero header.
				if reported != unix.EMSGSIZE {
					continue
				}
				covers := errno == unix.EMSGSIZE && !evidence.local && named.Addr() == dst.Addr() &&
					(named.Port() == 0 || named.Port() == dst.Port()) && s.exceeds(size, info)
				if covers {
					evidence.local, evidence.mtu = true, s.pathMTU(info)
				}
			case unix.SO_EE_ORIGIN_ICMP, unix.SO_EE_ORIGIN_ICMP6:
				if reported == 0 {
					continue
				}
				if errno != 0 && reported == errno {
					evidence.remote = true
				}
				message := platform.DatagramError{Destination: named}
				if reported == unix.EMSGSIZE {
					message.MTU = s.pathMTU(info)
				} else {
					// Unreachable, prohibited, parameter problem or time
					// exceeded: the shared contract has one unreachable form.
					message.Unreachable = true
				}
				if d.ready || (d.handler == nil && len(s.errors) == cap(s.errors)) {
					continue
				}
				message.Payload = append([]byte(nil), data[:n]...)
				if d.handler != nil {
					d.pending, d.ready = message, true
					continue
				}
				select {
				case s.errors <- message:
				default:
				}
			}
		}
	}
	return evidence
}

type errorScratch struct {
	data    [2048]byte
	control [256]byte
}

var errorBuffers = sync.Pool{New: func() any { return new(errorScratch) }}

// sendDatagram attributes a send failure. Linux latches every queued ICMP
// error in sk_err, and the next sendmsg returns it whatever that send's
// destination. Some of those errnos can also be this send's own synchronous
// result, so a failure is returned for the current destination only with
// proof. Otherwise it is a counted silent drop, never a fabricated ICMP.
//
// explain runs one bounded error-queue pass for the send's errno and clear
// consumes the latch. The send is retried at most once. routeLost says
// whether the socket's line binding has no usable route; nil means unknown.
func sendDatagram(send func() error, explain func(unix.Errno) errorEvidence, clear func(), routeLost func() bool) error {
	err := send()
	errno, ok := latchedErrno(err)
	if !ok {
		return localSendError(err)
	}
	first := explain(errno)
	// Even LOCAL reports may belong to an older send, left behind a bounded
	// drain. Ignore all first-pass MTU evidence. Only an empty queue followed
	// by a new send under errorMu establishes a fresh LOCAL report.
	clear()
	err = send()
	if errno, ok = latchedErrno(err); !ok {
		return localSendError(err)
	}
	// A new ICMP may set sk_err even when its error-queue allocation fails.
	// Absence of a quotation is not evidence of a local route failure. The
	// line's binding is: with no usable route the kernel refuses every send
	// with a route error, so a route error repeated right after the latch was
	// cleared is this send's own. Return it, so the app gets its unreachable
	// and fails fast instead of timing out. Without that proof it is a drop.
	if errno == unix.ENETUNREACH || errno == unix.EHOSTUNREACH {
		if routeLost != nil && routeLost() {
			return errno
		}
		return errRouteDropped
	}
	if !first.empty || errno != unix.EMSGSIZE {
		return platform.ErrDatagramDropped
	}
	second := explain(errno)
	if second.local {
		return &platform.TooBig{MTU: second.mtu}
	}
	return platform.ErrDatagramDropped
}

// latchedErrno returns errnos the Linux UDPv4/v6 ICMP handlers store in
// sk_err (net/ipv4/icmp.c icmp_err_convert, net/ipv6/icmp.c).
func latchedErrno(err error) (unix.Errno, bool) {
	var errno unix.Errno
	if !errors.As(err, &errno) {
		return 0, false
	}
	switch errno {
	case unix.ECONNREFUSED, unix.EHOSTUNREACH, unix.ENETUNREACH, unix.EPROTO, unix.EMSGSIZE,
		unix.EACCES, unix.ENOPROTOOPT, unix.EOPNOTSUPP, unix.EHOSTDOWN, unix.ENONET:
		return errno, true
	}
	return 0, false
}

func localSendError(err error) error {
	if errors.Is(err, unix.ENOBUFS) {
		return platform.ErrDatagramDropped
	}
	return err
}
func (s *udpSocket) ReadError(ctx context.Context) (platform.DatagramError, error) {
	select {
	case e := <-s.errors:
		return e, nil
	case <-ctx.Done():
		return platform.DatagramError{}, ctx.Err()
	case <-s.done:
		return platform.DatagramError{}, net.ErrClosed
	}
}

func (p *Platform) Echo(ctx context.Context, id string, dst netip.Addr, request []byte) ([]byte, error) {
	l, err := p.binding(id, dst.Is6())
	if err != nil {
		return nil, err
	}
	proto, family := unix.IPPROTO_ICMP, unix.AF_INET
	if dst.Is6() {
		proto, family = unix.IPPROTO_ICMPV6, unix.AF_INET6
	}
	fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, proto)
	if err != nil {
		if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
			if reason := pingPermission(); reason != nil {
				return nil, reason
			}
		}
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "ping socket")
	raw, err := f.SyscallConn()
	if err != nil {
		f.Close()
		return nil, err
	}
	if err := bindSocket(raw, l); err != nil {
		f.Close()
		return nil, err
	}
	conn, err := net.FilePacketConn(f)
	f.Close()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if _, err := conn.WriteTo(request, &net.UDPAddr{IP: net.IP(dst.AsSlice())}); err != nil {
		return nil, err
	}
	b := make([]byte, 9000)
	for {
		n, remote, err := conn.ReadFrom(b)
		if err != nil {
			return nil, err
		}
		a, ok := remote.(*net.UDPAddr)
		if !ok || !a.IP.Equal(net.IP(dst.AsSlice())) || n < 8 {
			continue
		}
		want := byte(0)
		if dst.Is6() {
			want = 129
		}
		if b[0] != want || b[1] != 0 || b[6] != request[6] || b[7] != request[7] {
			continue
		}
		return b[:n], nil
	}
}

func pingPermission() error {
	b, err := readKernelFile("/proc/sys/net/ipv4/ping_group_range", 128)
	if err != nil {
		return fmt.Errorf("cannot read ping_group_range: %w", err)
	}
	fields := strings.Fields(string(b))
	if len(fields) != 2 {
		return errors.New("invalid ping_group_range")
	}
	low, e1 := strconv.ParseUint(fields[0], 10, 32)
	high, e2 := strconv.ParseUint(fields[1], 10, 32)
	if e1 != nil || e2 != nil {
		return errors.New("invalid ping_group_range")
	}
	if low > 0 || high < low {
		return fmt.Errorf("ICMP echo unavailable: net.ipv4.ping_group_range=%s excludes engine gid 0; configure a range including 0", strings.TrimSpace(string(b)))
	}
	return nil
}
