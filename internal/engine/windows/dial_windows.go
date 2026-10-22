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
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/engine"
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
	udpRetries        portRetries
	tcpRetries        portRetries
	refusals          finalRefusals
	// nativeDial replaces pool.dial in tests that inject refusals.
	nativeDial        func(context.Context, Adapter, netip.Addr, netip.AddrPort) (*readySocket, error)
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
		s.Error = engine.Clip(err.Error(), 512)
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

// bindSocket is the Go dial path's Control hook. Only health probes and the
// tests' plain-Go controls use it; it sets exactly the line options of the
// engine's native sockets.
func bindSocket(a Adapter, v6 bool) func(string, string, syscall.RawConn) error {
	return func(network, _ string, raw syscall.RawConn) error {
		var callErr error
		err := raw.Control(func(fd uintptr) {
			callErr = setLineInterface(windows.Handle(fd), a, v6)
			if callErr == nil && strings.HasPrefix(network, "tcp") {
				// ConnectEx requires an explicit source bind. Let Windows reuse
				// ephemeral ports when its existing auto-reuse configuration
				// permits it; never change that machine-wide configuration.
				callErr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, soReuseUnicastPort, 1)
			}
		})
		return errors.Join(err, callErr)
	}
}

func (d *Dialer) DialTCP(ctx context.Context, line string, remote netip.AddrPort) (platform.TCPConn, error) {
	return d.DialFlowTCP(ctx, line, remote, platform.FlowIdentity{Destination: remote})
}

// DialFlowTCP dials a relay socket for flow. A refusal of the automatic port
// choice gets bounded fresh attempts (SYSTEM-DESIGN 5.9); one that still
// ends refused is counted and kept with the flow.
func (d *Dialer) DialFlowTCP(ctx context.Context, line string, remote netip.AddrPort, flow platform.FlowIdentity) (platform.TCPConn, error) {
	native := d.nativeDial
	if native == nil {
		if d.pool == nil {
			return nil, errors.New("Windows socket readiness was not initialized")
		}
		native = d.pool.dial
	}
	a, source, err := d.Routes.binding(line, remote.Addr().Is6())
	if err != nil {
		return nil, err
	}
	note, started := d.startDial(line, remote)
	c, outcome, err := retryOpen(&d.tcpRetries, portLimit, func() (*readySocket, error) { return native(ctx, a, source, remote) })
	var conn net.Conn
	if c != nil {
		conn = c
	}
	d.finishDial(note, started, conn, err)
	if err != nil {
		if outcome.Refused {
			flow.Destination = remote
			d.refusals.record("tcp", "flow", line, netip.AddrPortFrom(source, 0), flow, outcome.Attempts, err)
		}
		d.ports.observe(err)
		return nil, err
	}
	return c, nil
}

// dialProbe gives a health probe a Go connection with the line's exact bind
// options. Probes need blocking net.Conn I/O with deadlines (HTTP/TLS), which
// Go's network package already provides; this connection is never handed to
// the relay, so it is never copied and Go keeps its only descriptor.
func (d *Dialer) dialProbe(ctx context.Context, line string, remote netip.AddrPort) (net.Conn, error) {
	a, source, err := d.Routes.binding(line, remote.Addr().Is6())
	if err != nil {
		return nil, err
	}
	network := "tcp4"
	if remote.Addr().Is6() {
		network = "tcp6"
	}
	dial := net.Dialer{Timeout: tcpDialTimeout, LocalAddr: net.TCPAddrFromAddrPort(netip.AddrPortFrom(source, 0)),
		Control: bindSocket(a, remote.Addr().Is6()), KeepAlive: 30 * time.Second}
	note, started := d.startDial(line, remote)
	// A probe is the engine's own TCP dial too: the same fresh attempts.
	c, outcome, err := retryOpen(&d.tcpRetries, portLimit, func() (net.Conn, error) { return dial.DialContext(ctx, network, remote.String()) })
	d.finishDial(note, started, c, err)
	if err != nil {
		if outcome.Refused {
			d.refusals.record("tcp", "probe", line, netip.AddrPortFrom(source, 0), platform.FlowIdentity{Destination: remote}, outcome.Attempts, err)
		}
		d.ports.observe(err)
		return nil, err
	}
	tcp := c.(*net.TCPConn)
	owner, err := ownGoDescriptor(tcp, "probe TCP Go connection")
	if err != nil {
		return nil, errors.Join(err, tcp.Close())
	}
	return &probeConn{TCPConn: tcp, owner: owner}, nil
}

// probeConn records the Go descriptor's close with the ownership tripwire.
// HTTP and TLS may close a connection more than once; Go's own close stays
// the only one.
type probeConn struct {
	*net.TCPConn
	owner winhandle.Owner
	once  sync.Once
	err   error
}

func (c *probeConn) Close() error {
	c.once.Do(func() { c.err = c.owner.CloseGo("probe TCP Go connection close", c.TCPConn.Close) })
	return c.err
}

// udpSocket is the NAT's outbound datagram socket, created natively with one
// handle owned from birth. Watch registers that same handle with the shared
// event-select readiness; it is never associated with a completion port.
type udpSocket struct {
	mu     sync.Mutex
	handle winhandle.Owner
	v6     bool
	mtu    uint32
	luid   uint64
	local  netip.AddrPort
	pool   *udpReadiness
	watch  *udpWatch
	closed bool
	// Blocking calls before Watch poll the handle in short slices; Close
	// waits for every one of them to leave before closing it.
	waiters int
	left    *sync.Cond
}

// openUDP creates and binds one native datagram socket. Its options follow
// the old Go path exactly: Go's family defaults, the line's interface, the
// bind to the line's source, then no ICMP-driven receive errors.
func openUDP(a Adapter, local netip.AddrPort, pool *udpReadiness) (*udpSocket, error) {
	v6 := local.Addr().Is6()
	socket, err := newSocket(v6, windows.SOCK_DGRAM, "UDP native socket open")
	if err != nil {
		return nil, err
	}
	bound, err := prepareUDP(socket, a, local, v6)
	if err != nil {
		return nil, closeFailed(socket, "UDP native setup failure close", err)
	}
	s := &udpSocket{handle: socket, v6: v6, mtu: a.MTU, luid: a.LUID, local: bound, pool: pool}
	s.left = sync.NewCond(&s.mu)
	return s, nil
}

func prepareUDP(socket winhandle.Owner, a Adapter, local netip.AddrPort, v6 bool) (netip.AddrPort, error) {
	h := socket.Handle("UDP native socket setup")
	if err := setFamilyDefaults(h, v6, true); err != nil {
		return netip.AddrPort{}, err
	}
	if err := setLineInterface(h, a, v6); err != nil {
		return netip.AddrPort{}, err
	}
	if err := bindSource(h, local); err != nil {
		return netip.AddrPort{}, err
	}
	// Go disabled both reports on every UDP socket: an ICMP port or network
	// unreachable must not fail the mapping's next receive.
	for _, control := range [...]struct {
		name string
		code uint32
	}{{"SIO_UDP_CONNRESET", windows.SIO_UDP_CONNRESET}, {"SIO_UDP_NETRESET", windows.SIO_UDP_NETRESET}} {
		var off, returned uint32
		if err := windows.WSAIoctl(h, control.code, (*byte)(unsafe.Pointer(&off)), uint32(unsafe.Sizeof(off)), nil, 0, &returned, nil, 0); err != nil {
			return netip.AddrPort{}, os.NewSyscallError("WSAIoctl "+control.name, err)
		}
	}
	if err := setNonblocking(socket, "UDP native nonblocking"); err != nil {
		return netip.AddrPort{}, err
	}
	return localName(h)
}

func (d *Dialer) OpenUDP(ctx context.Context, line string, v6 bool) (platform.UDPConn, error) {
	return d.OpenFlowUDP(ctx, line, v6, platform.FlowIdentity{})
}

// OpenFlowUDP binds a relay socket for flow, with bounded fresh attempts
// after a refused automatic port choice (SYSTEM-DESIGN 5.9).
func (d *Dialer) OpenFlowUDP(ctx context.Context, line string, v6 bool, flow platform.FlowIdentity) (platform.UDPConn, error) {
	a, source, err := d.Routes.binding(line, v6)
	if err != nil {
		return nil, err
	}
	network := "udp4"
	if v6 {
		network = "udp6"
	}
	local := netip.AddrPortFrom(source, 0)
	s, outcome, err := retryOpen(&d.udpRetries, udpPortRefusal, func() (*udpSocket, error) { return openUDP(a, local, d.udp) })
	if err != nil {
		if outcome.Refused {
			d.refusals.record("udp", "flow", line, local, flow, outcome.Attempts, err)
		}
		err = &net.OpError{Op: "listen", Net: network, Addr: net.UDPAddrFromAddrPort(local), Err: err}
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
	return s, nil
}
func (s *udpSocket) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	for s.waiters != 0 {
		s.left.Wait()
	}
	var err error
	if s.watch != nil {
		s.watch.Detach()
		err = s.watch.err
	}
	return errors.Join(err, s.handle.SocketClose("UDP native socket close"))
}
func (s *udpSocket) LocalAddr() netip.AddrPort { return s.local }

// udpWaitSlice bounds each blocking poll before Watch, so Close and
// cancellation are seen promptly. The NAT never takes this path on Windows:
// it calls Watch first (internal/engine/udp startReady).
const udpWaitSlice = 10 * time.Millisecond

var udpWaitPoll = winsock.NewProc("WSAPoll")

func (s *udpSocket) wait(ctx context.Context, events int16, site string) error {
	for {
		s.mu.Lock()
		if s.closed || s.watch != nil {
			s.mu.Unlock()
			return net.ErrClosed
		}
		if err := ctx.Err(); err != nil {
			s.mu.Unlock()
			return err
		}
		rows := []pollFD{{Socket: s.handle.Handle(site), Events: events}}
		s.waiters++
		s.mu.Unlock()
		n, _, callErr := udpWaitPoll.Call(uintptr(unsafe.Pointer(&rows[0])), uintptr(len(rows)), uintptr(udpWaitSlice.Milliseconds()))
		s.mu.Lock()
		s.waiters--
		if s.waiters == 0 {
			s.left.Broadcast()
		}
		s.mu.Unlock()
		if int32(n) == -1 {
			return os.NewSyscallError("WSAPoll", callErr)
		}
		if n > 0 {
			return nil
		}
	}
}

// WaitReadable consumes nothing: WSAPoll only reports queued datagrams,
// including empty ones.
func (s *udpSocket) WaitReadable(ctx context.Context) error {
	return s.wait(ctx, pollRdNorm, "UDP readable wait")
}
func (s *udpSocket) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	for {
		if err := s.wait(context.Background(), pollRdNorm, "UDP blocking receive wait"); err != nil {
			return 0, netip.AddrPort{}, err
		}
		s.mu.Lock()
		if s.closed || s.watch != nil {
			s.mu.Unlock()
			return 0, netip.AddrPort{}, net.ErrClosed
		}
		n, from, err := s.receive(b, "UDP blocking receive")
		s.mu.Unlock()
		if !errors.Is(err, platform.ErrWouldBlock) {
			return n, from, err
		}
	}
}
func (s *udpSocket) WriteTo(b []byte, dst netip.AddrPort, df bool) (int, error) {
	for {
		s.mu.Lock()
		if s.closed || s.watch != nil {
			s.mu.Unlock()
			return 0, net.ErrClosed
		}
		n, err := s.send(b, dst, df, "first send")
		s.mu.Unlock()
		if !errors.Is(err, platform.ErrWouldBlock) {
			return n, err
		}
		if err := s.wait(context.Background(), pollWrNorm, "UDP blocking send wait"); err != nil {
			return 0, err
		}
	}
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
