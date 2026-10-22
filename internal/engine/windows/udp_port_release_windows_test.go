//go:build windows

package winengine

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// How soon can a closed UDP socket's port be bound again? At the port limit
// the engine's native sockets saw bursts of WSAENOBUFS right after a release,
// with ~1,000 ports shown free and success 200 ms later, while Go-created
// sockets at the same address never did. This measures, per constructor, the
// delay from close until the exact port binds again. Native only: no engine,
// no TUN; the binding is the matched baseline's (TestISP or loopback).
func TestUDPPortReleaseDelay(t *testing.T) {
	hosted(t)
	if os.Getenv("NETSWITCH_PORT_GATE") != "1" {
		t.Skip("runs with the hosted port fixtures")
	}
	index, source, _ := udpPairBinding(t)
	line := Adapter{Index4: index}
	local := netip.AddrPortFrom(netip.MustParseAddr(source), 0)
	iocp, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(iocp)
	config := net.ListenConfig{Control: bindSocket(line, false)}
	// Each variant opens one bound socket and returns its port and its close.
	type opener func() (int, func() error, error)
	native := func(nonblocking, associate bool) opener {
		return func() (int, func() error, error) {
			s, err := openUDP(line, local, nil)
			if err != nil {
				return 0, nil, err
			}
			h := s.handle.Handle("release probe")
			if !nonblocking {
				off := new(uint32)
				if code, _, callErr := ioctlsocketProc.Call(uintptr(h), fionbio, uintptr(unsafe.Pointer(off))); int32(code) != 0 {
					s.Close()
					return 0, nil, callErr
				}
			}
			if associate {
				if _, err := windows.CreateIoCompletionPort(h, iocp, 0, 0); err != nil {
					s.Close()
					return 0, nil, err
				}
				if err := windows.SetFileCompletionNotificationModes(h,
					windows.FILE_SKIP_SET_EVENT_ON_HANDLE|windows.FILE_SKIP_COMPLETION_PORT_ON_SUCCESS); err != nil {
					s.Close()
					return 0, nil, err
				}
			}
			return int(s.LocalAddr().Port()), s.Close, nil
		}
	}
	variants := []struct {
		name string
		open opener
	}{
		{"Go", func() (int, func() error, error) {
			packet, err := config.ListenPacket(context.Background(), "udp4", local.String())
			if err != nil {
				return 0, nil, err
			}
			return packet.LocalAddr().(*net.UDPAddr).Port, packet.Close, nil
		}},
		{"native, nonblocking (production)", native(true, false)},
		{"native, blocking", native(false, false)},
		{"native, nonblocking, on a completion port like Go", native(true, true)},
	}
	const trials = 200
	for _, v := range variants {
		var delays []time.Duration
		failures := map[string]int{}
		for range trials {
			port, closeIt, err := v.open()
			if err != nil {
				failures["open: "+err.Error()]++
				continue
			}
			if err := closeIt(); err != nil {
				failures["close: "+err.Error()]++
				continue
			}
			started := time.Now()
			target := netip.AddrPortFrom(local.Addr(), uint16(port))
			for {
				probe, err := config.ListenPacket(context.Background(), "udp4", target.String())
				if err == nil {
					probe.Close()
					delays = append(delays, time.Since(started))
					break
				}
				if time.Since(started) > 5*time.Second {
					failures["port did not return within 5 s: "+err.Error()]++
					break
				}
				time.Sleep(time.Millisecond)
			}
		}
		slices.Sort(delays)
		at := func(p int) int64 {
			if len(delays) == 0 {
				return -1
			}
			return delays[min(len(delays)-1, p*len(delays)/100)].Microseconds()
		}
		over := 0
		for _, d := range delays {
			if d > 10*time.Millisecond {
				over++
			}
		}
		evidence, _ := json.Marshal(map[string]any{"variant": v.name, "trials": trials, "returned": len(delays),
			"p50us": at(50), "p95us": at(95), "maxus": at(100), "over10ms": over, "failures": failures, "source": source})
		t.Logf("WINDOWS UDP PORT RELEASE %s", evidence)
	}
}
