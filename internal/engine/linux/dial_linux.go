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
	"sync"
	"syscall"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
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
	return c.(*net.TCPConn), nil
}
func (p *Platform) OpenUDP(ctx context.Context, id string, v6 bool) (platform.UDPConn, error) {
	l, err := p.binding(id, v6)
	if err != nil {
		return nil, err
	}
	family, address := "udp4", "0.0.0.0:0"
	if v6 {
		family, address = "udp6", "[::]:0"
	}
	address = ""
	for _, ip := range l.Addresses {
		if ip.Is6() == v6 && ip.IsGlobalUnicast() {
			address = net.JoinHostPort(ip.String(), "0")
			break
		}
	}
	if address == "" {
		return nil, fmt.Errorf("line %s has no usable source address", id)
	}
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
	return &udpSocket{conn: c, raw: raw, v6: v6, errors: make(chan platform.DatagramError, 16), done: make(chan struct{})}, nil
}

type udpSocket struct {
	conn             *net.UDPConn
	raw              syscall.RawConn
	v6               bool
	writeMu, errorMu sync.Mutex
	once             sync.Once
	errors           chan platform.DatagramError
	done             chan struct{}
}

func (s *udpSocket) LocalAddr() netip.AddrPort { return s.conn.LocalAddr().(*net.UDPAddr).AddrPort() }
func (s *udpSocket) Close() error              { s.once.Do(func() { close(s.done) }); return s.conn.Close() }
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
		mtu := s.drainErrors()
		if mtu == 0 {
			if s.v6 {
				mtu = 1280
			} else {
				mtu = 576
			}
		}
		return n, &platform.TooBig{MTU: mtu}
	}
	return n, err
}

// A single socket reader drains the error queue when the kernel wakes it with
// SO_ERROR. A second RawConn.Read would compete for Go's read lock and could
// starve replies. ReadError consumes bounded messages from this channel.
func (s *udpSocket) drainErrors() uint32 {
	s.errorMu.Lock()
	defer s.errorMu.Unlock()
	var mtu uint32
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
			message := platform.DatagramError{Destination: dst, Payload: append([]byte(nil), data[:n]...)}
			if errno == uint32(unix.EMSGSIZE) {
				message.MTU = info
				mtu = info
			} else {
				message.Unreachable = true
			}
			select {
			case s.errors <- message:
			default:
			}
		}
	}
	return mtu
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
