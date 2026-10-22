//go:build windows

package winengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The UDP option matrix (SYSTEM-DESIGN 5.9 open question, coordinator's
// round of 2026-10-22). At TestISP's address, plain Go sockets were never
// refused a reopen after the port limit; the engine path was, with WSAENOBUFS
// and ports free. One variant per process (the harness runs each in its own
// test process with a pause between), starting from a bare native socket and
// adding the engine's options one at a time, then all together:
//
//	WSASocket protocol 0, OVERLAPPED|NO_HANDLE_INHERIT   socket_windows.go:69
//	SO_BROADCAST (IPv4) / IPV6_V6ONLY                     socket_windows.go:90-95
//	IP_UNICAST_IF                                        socket_windows.go:48
//	bind to the line's source, port 0                    dial_windows.go:274
//	SIO_UDP_CONNRESET and SIO_UDP_NETRESET off           dial_windows.go:282
//	FIONBIO nonblocking                                   dial_windows.go:288
//	WSAEventSelect registration (Watch)                   udp_readiness_windows.go:26
//
// Not set by the engine on UDP: SO_EXCLUSIVEADDRUSE, buffer sizes,
// SO_REUSE_UNICASTPORT (TCP only, connect_windows.go:105). UDP sockets are
// unconnected. Go's own socket also joins an I/O completion port with skip
// modes, which ours does not; "iocp" adds that.
type controlOptions struct {
	protocol                                           int32
	broadcast, unicastIf, resetsOff, nonblocking, iocp bool
}

var controlVariants = map[string]controlOptions{
	"raw":            {},
	"raw+broadcast":  {broadcast: true},
	"raw+unicastif":  {unicastIf: true},
	"raw+resetsoff":  {resetsOff: true},
	"raw+fionbio":    {nonblocking: true},
	"raw+iocp":       {iocp: true},
	"raw+protocol17": {protocol: windows.IPPROTO_UDP},
	"all":            {broadcast: true, unicastIf: true, resetsOff: true, nonblocking: true},
	"all+protocol17": {protocol: windows.IPPROTO_UDP, broadcast: true, unicastIf: true, resetsOff: true, nonblocking: true},
	"golike":         {broadcast: true, unicastIf: true, resetsOff: true, iocp: true},
}

type controlSocket struct{ h windows.Handle }

func (c *controlSocket) Close() error { return windows.Closesocket(c.h) }

func openControlUDP(o controlOptions, line Adapter, local netip.AddrPort, port windows.Handle) (*controlSocket, error) {
	h, err := windows.WSASocket(windows.AF_INET, windows.SOCK_DGRAM, o.protocol, nil, 0, windows.WSA_FLAG_OVERLAPPED|windows.WSA_FLAG_NO_HANDLE_INHERIT)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	fail := func(err error) (*controlSocket, error) {
		windows.Closesocket(h)
		return nil, err
	}
	if o.broadcast {
		if err := windows.SetsockoptInt(h, windows.SOL_SOCKET, windows.SO_BROADCAST, 1); err != nil {
			return fail(err)
		}
	}
	if o.unicastIf {
		if err := setLineInterface(h, line, false); err != nil {
			return fail(err)
		}
	}
	if err := bindSource(h, local); err != nil {
		return fail(err)
	}
	if o.iocp {
		if _, err := windows.CreateIoCompletionPort(h, port, 0, 0); err != nil {
			return fail(err)
		}
		if err := windows.SetFileCompletionNotificationModes(h, windows.FILE_SKIP_SET_EVENT_ON_HANDLE|windows.FILE_SKIP_COMPLETION_PORT_ON_SUCCESS); err != nil {
			return fail(err)
		}
	}
	if o.resetsOff {
		for _, code := range []uint32{windows.SIO_UDP_CONNRESET, windows.SIO_UDP_NETRESET} {
			off, returned := new(uint32), new(uint32)
			if err := windows.WSAIoctl(h, code, (*byte)(unsafe.Pointer(off)), 4, nil, 0, returned, nil, 0); err != nil {
				return fail(err)
			}
		}
	}
	if o.nonblocking {
		on := new(uint32)
		*on = 1
		if code, _, err := ioctlsocketProc.Call(uintptr(h), fionbio, uintptr(unsafe.Pointer(on))); int32(code) != 0 {
			return fail(err)
		}
	}
	return &controlSocket{h: h}, nil
}

// controlProvider names the provider behind a socket, with its full
// SO_PROTOCOL_INFOW identity, for the evidence.
func controlProvider(h windows.Handle) string {
	info := new(windows.WSAProtocolInfo)
	size := int32(unsafe.Sizeof(*info))
	if err := windows.Getsockopt(h, windows.SOL_SOCKET, soProtocolInfoW, (*byte)(unsafe.Pointer(info)), &size); err != nil {
		return "unknown: " + err.Error()
	}
	chain := info.ProtocolChain.ChainEntries[:max(0, min(int(info.ProtocolChain.ChainLen), len(info.ProtocolChain.ChainEntries)))]
	return fmt.Sprintf("%s (provider %s, catalog %d, chain %d %v, protocol %d, service %#x/%#x/%#x/%#x, provider flags %#x, IFS %t)",
		windows.UTF16ToString(info.ProtocolName[:]), info.ProviderId.String(), info.CatalogEntryId,
		info.ProtocolChain.ChainLen, chain, info.Protocol, info.ServiceFlags1, info.ServiceFlags2, info.ServiceFlags3,
		info.ServiceFlags4, info.ProviderFlags, info.ServiceFlags1&windows.XP1_IFS_HANDLES != 0)
}

// inRangePorts hands out ports inside the dynamic UDP range that were free in
// one native table read and are not excluded: the "explicit" variants bind
// these instead of asking Windows for port 0. A port taken since the read is
// skipped (EADDRINUSE), never counted as a refusal.
type inRangePorts struct {
	t     *testing.T
	space *udpPortSpace
	free  []int
}

func (p *inRangePorts) refresh() {
	p.free = p.free[:0]
	if p.space == nil || p.space.Probe == nil || len(p.space.Probe.families) == 0 || p.space.Probe.families[0].DynamicRange == nil {
		return
	}
	family := p.space.Probe.families[0]
	_, used, err := nativeUDPSnapshot()
	if err != nil {
		return
	}
	inUse := make(map[int]bool, len(used[0]))
	for _, port := range used[0] {
		inUse[int(port)] = true
	}
	for port := family.DynamicRange.Start; port <= family.DynamicRange.End; port++ {
		excluded := false
		for _, r := range family.ExcludedRanges {
			excluded = excluded || (port >= r.Start && port <= r.End)
		}
		if !excluded && !inUse[port] {
			p.free = append(p.free, port)
		}
	}
}

// bind tries free in-range ports until one binds; only a non-EADDRINUSE error
// is returned (that is the refusal being measured).
func (p *inRangePorts) bind(open func(port int) (io.Closer, error)) (io.Closer, error) {
	for len(p.free) > 0 {
		port := p.free[0]
		p.free = p.free[1:]
		c, err := open(port)
		if err == nil {
			return c, nil
		}
		if !errors.Is(err, windows.WSAEADDRINUSE) {
			return nil, err
		}
	}
	p.refresh()
	if len(p.free) == 0 {
		return nil, fmt.Errorf("explicit in-range bind: %w", windows.WSAENOBUFS)
	}
	return p.bind(open)
}

// explicitHalves makes both halves of every pair bind a recorded free port
// inside the dynamic range instead of asking Windows for port 0.
func explicitHalves(halves *udpEngineHalves, ports *inRangePorts, engine func(port int) (io.Closer, error)) {
	halves.custom = func() (io.Closer, error) { return ports.bind(engine) }
	halves.app = func(peer *net.UDPAddr) (*net.UDPConn, error) {
		c, err := ports.bind(func(p int) (io.Closer, error) {
			conn, err := net.DialUDP("udp4", &net.UDPAddr{Port: p}, peer)
			if err != nil {
				return nil, err
			}
			return conn, nil
		})
		if err != nil {
			return nil, err
		}
		return c.(*net.UDPConn), nil
	}
}

func TestUDPControlVariant(t *testing.T) {
	hosted(t)
	name := os.Getenv("NETSWITCH_UDP_CONTROL_VARIANT")
	if os.Getenv("NETSWITCH_PORT_GATE") != "1" || name == "" {
		t.Skip("one variant per process, run by tests/windows/udp-control-matrix.mjs")
	}
	cycles := udpRecoveryCycleCount()
	if cycles == 0 {
		t.Fatal("NETSWITCH_UDP_RECOVERY_CYCLES is required")
	}
	index, source, peerSource := udpPairBinding(t)
	line := Adapter{Index4: index}
	local := netip.AddrPortFrom(netip.MustParseAddr(source), 0)
	pool, err := newUDPReadiness(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.close()
	port, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(port)
	halves := newUDPEngineHalves(true, index, source, pool)
	provider := ""
	// explicit, set for the ":explicit" variants, takes over both halves for
	// the recovery cycles after an ordinary automatic fill.
	var explicit func(space *udpPortSpace)
	base, explicitMode := name, false
	if before, ok := strings.CutSuffix(name, ":explicit"); ok {
		base, explicitMode = before, true
	}
	switch base {
	case "go":
		halves = newUDPEngineHalves(false, index, source, pool)
		halves.label = "plain Go socket"
	case "go+fionbio":
		// Go's own socket and overlapped I/O, plus only FIONBIO after bind.
		goHalves := newUDPEngineHalves(false, index, source, pool)
		halves = goHalves
		halves.label = "plain Go socket + FIONBIO only"
		halves.custom = func() (io.Closer, error) {
			conn, err := goHalves.openGo()
			if err != nil {
				return nil, err
			}
			raw, err := conn.SyscallConn()
			if err != nil {
				conn.Close()
				return nil, err
			}
			var ioctlErr error
			if err := raw.Control(func(fd uintptr) {
				on := new(uint32)
				*on = 1
				if code, _, callErr := ioctlsocketProc.Call(fd, fionbio, uintptr(unsafe.Pointer(on))); int32(code) != 0 {
					ioctlErr = os.NewSyscallError("ioctlsocket FIONBIO", callErr)
				}
			}); err != nil || ioctlErr != nil {
				conn.Close()
				return nil, errors.Join(err, ioctlErr)
			}
			return conn, nil
		}
	case "production":
		halves.unwatched, halves.label = true, "production constructor, not registered"
	case "production+watch":
		halves.label = "production constructor, registered (Watch)"
	default:
		options, ok := controlVariants[base]
		if !ok {
			t.Fatalf("unknown variant %q", name)
		}
		halves.label = "native " + base
		halves.custom = func() (io.Closer, error) {
			s, err := openControlUDP(options, line, local, port)
			if err != nil {
				return nil, err
			}
			if provider == "" {
				provider = controlProvider(s.h)
			}
			return s, nil
		}
		if explicitMode {
			explicit = func(space *udpPortSpace) {
				explicitHalves(&halves, &inRangePorts{t: t, space: space}, func(p int) (io.Closer, error) {
					return openControlUDP(options, line, netip.AddrPortFrom(local.Addr(), uint16(p)), port)
				})
			}
		}
	}
	if explicitMode && base == "go" {
		goHalves := halves
		explicit = func(space *udpPortSpace) {
			explicitHalves(&halves, &inRangePorts{t: t, space: space}, func(p int) (io.Closer, error) {
				packet, err := goHalves.config.ListenPacket(context.Background(), "udp4", netip.AddrPortFrom(local.Addr(), uint16(p)).String())
				if err != nil {
					return nil, err
				}
				return packet.(*net.UDPConn), nil
			})
		}
	}
	if explicitMode && explicit == nil {
		t.Fatalf("variant %q has no explicit-port form", name)
	}
	if explicitMode {
		halves.label += ", explicit in-range ports in the cycles"
	}
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: peerSource})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	var apps []*net.UDPConn
	var engines []io.Closer
	defer func() {
		for _, app := range apps {
			app.Close()
		}
		for _, engine := range engines {
			engine.Close()
		}
	}()
	// Fill to the OS limit with app/engine pairs, no traffic: occupancy only.
	var limit error
	for range 12000 {
		app, err := net.DialUDP("udp4", nil, peer.LocalAddr().(*net.UDPAddr))
		if err != nil {
			limit = err
			break
		}
		engine, err := halves.open()
		if err != nil {
			app.Close()
			limit = err
			break
		}
		if provider == "" {
			if s, ok := engine.(*udpSocket); ok {
				provider = controlProvider(s.handle.Handle("matrix provider"))
			} else if c, ok := engine.(*net.UDPConn); ok {
				if raw, err := c.SyscallConn(); err == nil {
					raw.Control(func(fd uintptr) { provider = controlProvider(windows.Handle(fd)) })
				}
			}
		}
		apps, engines = append(apps, app), append(engines, engine)
	}
	if !portLimit(limit) {
		t.Fatalf("variant %s: pair limit not established: %v", name, limit)
	}
	space := diagnoseUDPPortSpace(context.Background())
	held := len(apps)
	if explicit != nil {
		explicit(space)
	}
	nativeUDPRecoveryCycles(t, cycles, halves, &apps, &engines, peer, source, space)
	evidence, _ := json.Marshal(map[string]any{"variant": name, "socket": halves.kind(), "provider": provider,
		"heldPairs": held, "limit": limit.Error(), "source": source})
	t.Logf("WINDOWS UDP CONTROL VARIANT %s", evidence)
}
