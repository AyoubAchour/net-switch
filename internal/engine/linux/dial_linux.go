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

type tcpSocket struct {
	*net.TCPConn
	raw syscall.RawConn
}

// Peek without consuming: the relay borrows its buffer only after data, EOF
// or an error is ready. RawConn.Read waits through Go's poller and Close wakes
// it, so no polling goroutine or per-idle-flow payload buffer is necessary.
func (s *tcpSocket) WaitReadable(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var readErr error
	var peek [1]byte
	err := s.raw.Read(func(fd uintptr) bool {
		_, _, readErr = unix.Recvfrom(int(fd), peek[:], unix.MSG_PEEK|unix.MSG_DONTWAIT)
		return readErr != unix.EAGAIN && readErr != unix.EWOULDBLOCK
	})
	return errors.Join(err, readErr)
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
	return &udpSocket{conn: c, raw: raw, v6: v6, errors: make(chan platform.DatagramError, 1), done: make(chan struct{})}, nil
}

type mtuEntry struct {
	destination netip.Addr
	mtu         uint32
}

type udpSocket struct {
	conn             *net.UDPConn
	raw              syscall.RawConn
	v6               bool
	writeMu, errorMu sync.Mutex
	once             sync.Once
	errors           chan platform.DatagramError
	done             chan struct{}
	mtus             [8]mtuEntry
	mtuCursor        int
	handler          func(platform.DatagramError)
}

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
	n, err := s.conn.WriteToUDPAddrPort(b, dst)
	if errors.Is(err, unix.EMSGSIZE) {
		return n, s.tooBig(dst)
	}
	return n, err
}

func (s *udpSocket) tooBig(dst netip.AddrPort) *platform.TooBig {
	s.drainErrors()
	s.errorMu.Lock()
	var mtu uint32
	for _, entry := range s.mtus {
		if entry.destination == dst.Addr() {
			mtu = entry.mtu
			break
		}
	}
	s.errorMu.Unlock()
	if mtu == 0 {
		if s.v6 {
			mtu = 1280
		} else {
			mtu = 576
		}
	}
	return &platform.TooBig{MTU: mtu}
}

// A single socket reader drains the error queue when the kernel wakes it with
// SO_ERROR. A second RawConn.Read would compete for Go's read lock and could
// starve replies. ReadError consumes bounded messages from this channel.
func (s *udpSocket) drainErrors() {
	s.errorMu.Lock()
	handler := s.handler
	var pending *platform.DatagramError
	defer func() {
		s.errorMu.Unlock()
		if handler != nil && pending != nil {
			handler(*pending)
		}
	}()
	for i := 0; i < 16; i++ {
		var data [2048]byte
		var control [256]byte
		var n, oob int
		var from unix.Sockaddr
		var err error
		e := s.raw.Control(func(fd uintptr) {
			n, oob, _, from, err = unix.Recvmsg(int(fd), data[:], control[:], unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
		})
		if e != nil || err != nil {
			break
		}
		var dst netip.AddrPort
		switch a := from.(type) {
		case *unix.SockaddrInet4:
			dst = netip.AddrPortFrom(netip.AddrFrom4(a.Addr), uint16(a.Port))
		case *unix.SockaddrInet6:
			dst = netip.AddrPortFrom(netip.AddrFrom16(a.Addr), uint16(a.Port))
		}
		if !dst.IsValid() {
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
			errno := binary.NativeEndian.Uint32(m.Data)
			info := binary.NativeEndian.Uint32(m.Data[8:])
			message := platform.DatagramError{Destination: dst}
			if errno == uint32(unix.EMSGSIZE) {
				message.MTU = info
				if info != 0 {
					index := s.mtuCursor % len(s.mtus)
					for i, entry := range s.mtus {
						if entry.destination == dst.Addr() {
							index = i
							break
						}
					}
					s.mtus[index] = mtuEntry{dst.Addr(), info}
					s.mtuCursor++
				}
			} else {
				message.Unreachable = true
			}
			// LOCAL errors belong to the synchronous WriteTo failure. Linux
			// may supply no UDP port or payload there. Keep the MTU above, but
			// let the sender quote its original packet instead of emitting a
			// second ICMP response with a fabricated port-zero UDP header.
			if m.Data[4] == unix.SO_EE_ORIGIN_LOCAL {
				continue
			}
			if (handler != nil && pending != nil) || (handler == nil && len(s.errors) == cap(s.errors)) {
				continue
			}
			message.Payload = append([]byte(nil), data[:n]...)
			if handler != nil {
				pending = &message
				continue
			}
			select {
			case s.errors <- message:
			default:
			}
		}
	}
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
