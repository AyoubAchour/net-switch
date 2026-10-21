//go:build windows

package winengine

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

type Dialer struct {
	Routes            *Routes
	pool              *readiness
	udp               *udpReadiness
	ports             *portDiagnostics
	udpExhaustions    atomic.Uint64
	udpLastLog        atomic.Int64
	udpFailureStarted atomic.Bool
	udpFailure        atomic.Pointer[udpAllocationFailure]
	reservations      reservationJobs
	tcpDials          atomic.Uint64
	slowDials         atomic.Uint64
	slowMu            sync.Mutex
	slowRecent        []slowDial
	inFlight          map[*slowDial]time.Time
}

// Diagnostics only: a TCP dial that takes this long is recorded with its
// outcome, and one still running that long is listed by the stats. The
// OS-limit gate measures resets against a ~2 s native refusal, and a dial
// that outlives it leaves the app's SYN unanswered.
const slowDialAfter = time.Second

type slowDial struct {
	AtUnixMilli int64   `json:"at"`
	Line        string  `json:"line"`
	Remote      string  `json:"remote"`
	Local       string  `json:"local,omitempty"`
	MS          float64 `json:"ms"`
	Error       string  `json:"error,omitempty"`
}

func (d *Dialer) startDial(line string, remote netip.AddrPort) (*slowDial, time.Time) {
	started := time.Now()
	s := &slowDial{AtUnixMilli: started.UnixMilli(), Line: line, Remote: remote.String()}
	d.slowMu.Lock()
	if d.inFlight == nil {
		d.inFlight = map[*slowDial]time.Time{}
	}
	d.inFlight[s] = started
	d.slowMu.Unlock()
	return s, started
}

func (d *Dialer) finishDial(s *slowDial, started time.Time, c net.Conn, err error) {
	d.tcpDials.Add(1)
	took := time.Since(started)
	d.slowMu.Lock()
	defer d.slowMu.Unlock()
	delete(d.inFlight, s)
	if took < slowDialAfter {
		return
	}
	d.slowDials.Add(1)
	s.MS = float64(took.Microseconds()) / 1000
	if c != nil {
		s.Local = c.LocalAddr().String()
	}
	if err != nil {
		s.Error = err.Error()
	}
	if len(d.slowRecent) == 32 {
		d.slowRecent = append(d.slowRecent[:0], d.slowRecent[1:]...)
	}
	d.slowRecent = append(d.slowRecent, *s)
}

// Stats reports the dialer's diagnostics through the engine's optional hook.
func (d *Dialer) Stats() any {
	d.slowMu.Lock()
	defer d.slowMu.Unlock()
	recent := append([]slowDial(nil), d.slowRecent...)
	var running []slowDial
	for s, started := range d.inFlight {
		if took := time.Since(started); took >= slowDialAfter && len(running) < 32 {
			r := *s
			r.MS = float64(took.Microseconds()) / 1000
			running = append(running, r)
		}
	}
	return map[string]any{"tcpDials": d.tcpDials.Load(), "slowTCPDials": d.slowDials.Load(), "slowRecent": recent,
		"inFlight": len(d.inFlight), "slowInFlight": running}
}

func NewDialer(routes *Routes) (*Dialer, error) {
	pool, err := newReadiness()
	if err != nil {
		return nil, err
	}
	udp, err := newUDPReadiness(func(err error) {
		if routes != nil && routes.Fatal != nil {
			routes.Fatal(err)
		}
	})
	if err != nil {
		pool.close()
		return nil, err
	}
	return &Dialer{Routes: routes, pool: pool, udp: udp, ports: newPortDiagnostics()}, nil
}

func (d *Dialer) Close() error {
	d.reservations.close()
	if d.ports != nil {
		d.ports.close()
	}
	var err error
	if d.pool != nil {
		err = d.pool.close()
	}
	if d.udp != nil {
		err = errors.Join(err, d.udp.close())
	}
	return err
}

func bindSocket(a Adapter, v6 bool) func(string, string, syscall.RawConn) error {
	return func(network, _ string, raw syscall.RawConn) error {
		var callErr error
		err := raw.Control(func(fd uintptr) {
			level, index := windows.IPPROTO_IP, a.Index4
			if v6 {
				level, index = windows.IPPROTO_IPV6, a.Index6
			} else {
				var b [4]byte
				binary.BigEndian.PutUint32(b[:], index)
				index = binary.LittleEndian.Uint32(b[:])
			}
			callErr = windows.SetsockoptInt(windows.Handle(fd), level, 31, int(index))
			if callErr == nil && strings.HasPrefix(network, "tcp") {
				// ConnectEx requires an explicit source bind. Let Windows reuse
				// ephemeral ports when its existing auto-reuse configuration
				// permits it; never change that machine-wide configuration.
				callErr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, 0x3007, 1) // SO_REUSE_UNICASTPORT.
			}
		})
		return errors.Join(err, callErr)
	}
}

func (d *Dialer) DialTCP(ctx context.Context, line string, remote netip.AddrPort) (platform.TCPConn, error) {
	if d.pool == nil {
		return nil, errors.New("Windows socket readiness was not initialized")
	}
	a, source, err := d.Routes.binding(line, remote.Addr().Is6())
	if err != nil {
		return nil, err
	}
	network := "tcp4"
	if remote.Addr().Is6() {
		network = "tcp6"
	}
	dial := net.Dialer{Timeout: 10 * time.Second, LocalAddr: net.TCPAddrFromAddrPort(netip.AddrPortFrom(source, 0)),
		Control: bindSocket(a, remote.Addr().Is6()), KeepAlive: 30 * time.Second}
	note, started := d.startDial(line, remote)
	c, err := dial.DialContext(ctx, network, remote.String())
	d.finishDial(note, started, c, err)
	if err != nil {
		d.ports.observe(err)
		return nil, err
	}
	return &readySocket{blocking: c.(*net.TCPConn), pool: d.pool, local: c.LocalAddr(), remote: c.RemoteAddr()}, nil
}

type udpSocket struct {
	conn    *net.UDPConn
	raw     syscall.RawConn
	mu      sync.Mutex
	v6      bool
	mtu     uint32
	luid    uint64
	local   netip.AddrPort
	pool    *udpReadiness
	watch   *udpWatch
	handle  winhandle.Owner
	goOwner winhandle.Owner
	closed  bool
}

func (d *Dialer) OpenUDP(ctx context.Context, line string, v6 bool) (platform.UDPConn, error) {
	a, source, err := d.Routes.binding(line, v6)
	if err != nil {
		return nil, err
	}
	network := "udp4"
	if v6 {
		network = "udp6"
	}
	lc := net.ListenConfig{Control: bindSocket(a, v6)}
	c, err := lc.ListenPacket(ctx, network, netip.AddrPortFrom(source, 0).String())
	if err != nil {
		if portLimit(err) {
			total := d.udpExhaustions.Add(1)
			d.captureUDPAllocationFailure(line, source, a, err)
			second := time.Now().Unix()
			old := d.udpLastLog.Load()
			if old != second && d.udpLastLog.CompareAndSwap(old, second) {
				log.Printf("Windows UDP socket allocation failed; refused=%d; bound socket failed: %v", total, err)
			}
		}
		return nil, err
	}
	u := c.(*net.UDPConn)
	raw, err := u.SyscallConn()
	if err != nil {
		u.Close()
		return nil, err
	}
	return &udpSocket{conn: u, raw: raw, v6: v6, mtu: a.MTU, luid: a.LUID,
		local: u.LocalAddr().(*net.UDPAddr).AddrPort(), pool: d.udp}, nil
}
func (s *udpSocket) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.watch == nil {
		if s.goOwner.IsZero() {
			var err error
			s.goOwner, err = ownGoDescriptor(s.conn, "UDP Go connection before close")
			if err != nil {
				return err
			}
		}
		return s.goOwner.CloseGo("UDP Go connection close", s.conn.Close)
	}
	s.watch.Detach()
	return errors.Join(s.watch.err, s.handle.SocketClose("UDP native socket close"))
}
func (s *udpSocket) LocalAddr() netip.AddrPort { return s.local }
func (s *udpSocket) WaitReadable(ctx context.Context) error {
	s.mu.Lock()
	transferred, closed := s.watch != nil, s.closed
	s.mu.Unlock()
	if closed || transferred {
		return net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	cancelled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		s.conn.SetReadDeadline(time.Now())
		close(cancelled)
	})
	defer func() {
		if !stop() {
			<-cancelled
		}
		s.conn.SetReadDeadline(time.Time{})
	}()
	waited := false
	// Go 1.27's Windows RawRead waits with a zero-byte overlapped MSG_PEEK
	// for datagram sockets. It consumes nothing, including zero-byte UDP.
	err := s.raw.Read(func(uintptr) bool {
		if waited {
			return true
		}
		waited = true
		return false
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
func (s *udpSocket) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	s.mu.Lock()
	transferred, closed := s.watch != nil, s.closed
	s.mu.Unlock()
	if closed || transferred {
		return 0, netip.AddrPort{}, net.ErrClosed
	}
	n, addr, err := s.conn.ReadFromUDPAddrPort(b)
	if platform.IsTooBig(err) {
		err = &platform.TooBig{MTU: s.mtu}
	}
	return n, addr, err
}
func (s *udpSocket) WriteTo(b []byte, dst netip.AddrPort, df bool) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.watch != nil {
		return 0, net.ErrClosed
	}
	var optionErr error
	err := s.raw.Control(func(fd uintptr) {
		optionErr = s.fragmentation(windows.Handle(fd), df)
	})
	if err != nil || optionErr != nil {
		err = errors.Join(err, optionErr)
		noteUDPSendFailure("first send fragmentation option", dst, err)
		return 0, err
	}
	n, err := s.conn.WriteToUDPAddrPort(b, dst)
	if errors.Is(err, windows.WSAENOBUFS) {
		return n, platform.ErrDatagramDropped
	}
	if platform.IsTooBig(err) {
		err = &platform.TooBig{MTU: s.pathMTU(dst.Addr())}
	}
	noteUDPSendFailure("first send", dst, err)
	return n, err
}

func (s *udpSocket) fragmentation(fd windows.Handle, df bool) error {
	level, value := windows.IPPROTO_IP, 0
	if s.v6 {
		level, value = windows.IPPROTO_IPV6, 1
	} else if df {
		value = 1
	}
	return windows.SetsockoptInt(fd, level, 14, value) // IP_DONTFRAGMENT / IPV6_DONTFRAG.
}

// MIB_IPPATH_ROW, from netioapi.h. Both supported architectures use the same
// 136-byte layout; SOCKADDR_INET has four-byte alignment and NET_LUID has eight.
type pathRow struct {
	Source, Destination                       windows.RawSockaddrInet
	LUID                                      uint64
	Index                                     uint32
	NextHop                                   windows.RawSockaddrInet
	MTU, RTTMean, RTTDeviation, LastReachable uint32
	Reachable                                 byte
	TransmitSpeed, ReceiveSpeed               uint64
}

func (s *udpSocket) pathMTU(destination netip.Addr) uint32 {
	mtu := s.mtu
	family := uint16(windows.AF_INET)
	if s.v6 {
		family = windows.AF_INET6
	}
	iface := windows.MibIpInterfaceRow{Family: family, InterfaceLuid: s.luid}
	if err := windows.GetIpInterfaceEntry(&iface); err == nil && iface.NlMtu != 0 {
		mtu = iface.NlMtu
	}
	row := pathRow{Source: sockaddr(s.LocalAddr().Addr()), Destination: sockaddr(destination), LUID: s.luid}
	if err := api("GetIpPathEntry", uintptr(unsafe.Pointer(&row))); err == nil && row.MTU != 0 {
		if mtu == 0 || row.MTU < mtu {
			mtu = row.MTU
		}
	}
	if mtu == 0 {
		if s.v6 {
			return 1280
		}
		return 576
	}
	return mtu
}

// Avoid importing a second Winsock binding package for the two ICMP APIs.
type ipOptions struct {
	TTL, TOS, Flags, Size byte
	Data                  *byte
}
type echoReply struct {
	Address, Status, RoundTrip uint32
	DataSize, Reserved         uint16
	Data                       *byte
	Options                    ipOptions
}

func (d *Dialer) Echo(ctx context.Context, line string, destination netip.Addr, request []byte) ([]byte, error) {
	a, source, err := d.Routes.binding(line, destination.Is6())
	if err != nil {
		return nil, err
	}
	if len(request) < 8 || len(request) > 9000 {
		return nil, errors.New("invalid echo size")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	create := "IcmpCreateFile"
	if destination.Is6() {
		create = "Icmp6CreateFile"
	}
	h, _, callErr := iphlp.NewProc(create).Call()
	if h == uintptr(windows.InvalidHandle) {
		return nil, callErr
	}
	icmpOwner := winhandle.Open(windows.Handle(h), "ICMP echo handle open")
	defer icmpOwner.Close("ICMP echo handle close", func(value windows.Handle) error {
		ok, _, err := iphlp.NewProc("IcmpCloseHandle").Call(uintptr(value))
		if ok == 0 {
			return err
		}
		return nil
	})
	payload := request[8:]
	// ICMP_ECHO_REPLY and the API's IO_STATUS_BLOCK need pointer alignment.
	// Pin all payload storage explicitly, including a caller's stack-sized
	// request. Neither an integer pointer nor KeepAlive alone forces escape.
	words := make([]uint64, (len(payload)+256+7)/8)
	reply := unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), len(words)*8)
	var pinned runtime.Pinner
	pinned.Pin(&words[0])
	if len(payload) != 0 {
		pinned.Pin(&payload[0])
	}
	defer pinned.Unpin()
	options := ipOptions{TTL: 64}
	var data uintptr
	if len(payload) != 0 {
		data = uintptr(unsafe.Pointer(&payload[0]))
	}
	timeout := uint32(3000)
	if until, ok := ctx.Deadline(); ok {
		timeout = uint32(max(1, min(3000, time.Until(until).Milliseconds())))
	}
	var count uintptr
	if destination.Is6() {
		src := windows.RawSockaddrInet6{Family: windows.AF_INET6, Addr: source.As16()}
		if source.IsLinkLocalUnicast() {
			src.Scope_id = a.Index6
		}
		dst := windows.RawSockaddrInet6{Family: windows.AF_INET6, Addr: destination.As16()}
		count, _, callErr = iphlp.NewProc("Icmp6SendEcho2").Call(uintptr(icmpOwner.Handle("ICMPv6 echo")), 0, 0, 0,
			uintptr(unsafe.Pointer(&src)), uintptr(unsafe.Pointer(&dst)), data, uintptr(len(payload)),
			uintptr(unsafe.Pointer(&options)), uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(timeout))
	} else {
		src, dst := source.As4(), destination.As4()
		count, _, callErr = iphlp.NewProc("IcmpSendEcho2Ex").Call(uintptr(icmpOwner.Handle("ICMPv4 echo")), 0, 0, 0,
			uintptr(binary.LittleEndian.Uint32(src[:])), uintptr(binary.LittleEndian.Uint32(dst[:])),
			data, uintptr(len(payload)), uintptr(unsafe.Pointer(&options)), uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(timeout))
	}
	// Event and APC are both nil: the documented synchronous API completes
	// before returning, including timeout. The old async path could time out
	// its event wait and release a reply buffer still owned by the kernel.
	// The native timeout remains capped at three seconds, as before; engine
	// shutdown joins its bounded echo workers before releasing the dialer.
	if count == 0 {
		return nil, fmt.Errorf("native ICMP echo failed: %w", callErr)
	}
	out := append([]byte(nil), request...)
	if destination.Is6() {
		// ICMPV6_ECHO_REPLY contains IPV6_ADDRESS_EX (26 bytes, padded to 28),
		// status, RTT; data follows the fixed 36-byte header.
		if binary.LittleEndian.Uint32(reply[28:]) != 0 {
			return nil, errors.New("IPv6 echo failed")
		}
		copy(out[8:], reply[36:36+len(payload)])
		out[0] = 129
	} else {
		r := (*echoReply)(unsafe.Pointer(&reply[0]))
		if r.Status != 0 || int(r.DataSize) != len(payload) {
			return nil, errors.New("IPv4 echo failed")
		}
		if len(payload) != 0 {
			start, base := uintptr(unsafe.Pointer(r.Data)), uintptr(unsafe.Pointer(&reply[0]))
			if start < base || start-base+uintptr(r.DataSize) > uintptr(len(reply)) {
				return nil, errors.New("invalid ICMP reply buffer")
			}
			copy(out[8:], unsafe.Slice(r.Data, int(r.DataSize)))
		}
		out[0] = 0
	}
	return out, nil
}
