//go:build windows

package winengine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
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

// controlProvider names the provider behind a socket, for the evidence.
func controlProvider(h windows.Handle) string {
	info := new(windows.WSAProtocolInfo)
	size := int32(unsafe.Sizeof(*info))
	if err := windows.Getsockopt(h, windows.SOL_SOCKET, soProtocolInfoW, (*byte)(unsafe.Pointer(info)), &size); err != nil {
		return "unknown: " + err.Error()
	}
	return fmt.Sprintf("%s (catalog %d, protocol %d, IFS %t)", windows.UTF16ToString(info.ProtocolName[:]),
		info.CatalogEntryId, info.Protocol, info.ServiceFlags1&windows.XP1_IFS_HANDLES != 0)
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
	switch name {
	case "go":
		halves = newUDPEngineHalves(false, index, source, pool)
		halves.label = "plain Go socket"
	case "production":
		halves.unwatched, halves.label = true, "production constructor, not registered"
	case "production+watch":
		halves.label = "production constructor, registered (Watch)"
	default:
		options, ok := controlVariants[name]
		if !ok {
			t.Fatalf("unknown variant %q", name)
		}
		halves.label = "native " + name
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
	nativeUDPRecoveryCycles(t, cycles, halves, &apps, &engines, peer, source, space)
	evidence, _ := json.Marshal(map[string]any{"variant": name, "socket": halves.kind(), "provider": provider,
		"heldPairs": held, "limit": limit.Error(), "source": source})
	t.Logf("WINDOWS UDP CONTROL VARIANT %s", evidence)
}
