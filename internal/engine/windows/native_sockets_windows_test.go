//go:build windows

package winengine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

// loopbackLine returns the loopback interface as a line, so tests create
// sockets through the engine's production constructors with real line options.
func loopbackLine(t *testing.T) Adapter {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range interfaces {
		if item.Flags&net.FlagLoopback != 0 {
			return Adapter{Index4: uint32(item.Index), Index6: uint32(item.Index), MTU: 65535}
		}
	}
	t.Fatal("no loopback interface")
	return Adapter{}
}

func loopbackSource(v6 bool) netip.Addr {
	if v6 {
		return netip.IPv6Loopback()
	}
	return netip.MustParseAddr("127.0.0.1")
}

func unmapped(a netip.AddrPort) netip.AddrPort { return netip.AddrPortFrom(a.Addr().Unmap(), a.Port()) }

// dialNative connects through the engine's TCP constructor (line options,
// bind, ConnectEx on pool) to listener and accepts the peer.
func dialNative(t *testing.T, pool *readiness, listener *net.TCPListener) (*readySocket, *net.TCPConn) {
	t.Helper()
	remote := unmapped(listener.Addr().(*net.TCPAddr).AddrPort())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := pool.dial(ctx, loopbackLine(t), loopbackSource(remote.Addr().Is6()), remote)
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		c.Close()
		t.Fatal(err)
	}
	peer, err := listener.AcceptTCP()
	if err != nil {
		c.Close()
		t.Fatal(err)
	}
	if unmapped(peer.RemoteAddr().(*net.TCPAddr).AddrPort()) != c.local.(*net.TCPAddr).AddrPort() {
		c.Close()
		peer.Close()
		t.Fatalf("native socket reported local %s, peer saw %s", c.local, peer.RemoteAddr())
	}
	return c, peer
}

// nativeTCPPair is dialNative to a fresh loopback listener, with the relay's
// Watch already installed.
func nativeTCPPair(t *testing.T, pool *readiness, network string, wake func()) (*readySocket, *net.TCPConn) {
	t.Helper()
	ip := net.IPv4(127, 0, 0, 1)
	if network == "tcp6" {
		ip = net.IPv6loopback
	}
	listener, err := net.ListenTCP(network, &net.TCPAddr{IP: ip})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	c, peer := dialNative(t, pool, listener)
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	t.Cleanup(func() { peer.Close() })
	if err := peer.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Watch(wake); err != nil {
		t.Fatal(err)
	}
	return c, peer
}

// openNativeUDP opens a loopback datagram socket through the engine's UDP
// constructor.
func openNativeUDP(t *testing.T, pool *udpReadiness, v6 bool) *udpSocket {
	t.Helper()
	s, err := openUDP(loopbackLine(t), netip.AddrPortFrom(loopbackSource(v6), 0), pool)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type socketOption struct {
	name       string
	level, opt int
}

func readOptions(h windows.Handle, options []socketOption) map[string]string {
	values := map[string]string{}
	for _, option := range options {
		value, err := windows.GetsockoptInt(h, option.level, option.opt)
		if err != nil {
			values[option.name] = "error " + err.Error()
		} else {
			values[option.name] = fmt.Sprint(value)
		}
	}
	return values
}

func goOptions(t *testing.T, conn syscall.Conn, options []socketOption) map[string]string {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]string
	if err := raw.Control(func(fd uintptr) { values = readOptions(windows.Handle(fd), options) }); err != nil {
		t.Fatal(err)
	}
	return values
}

// socketProvider names the catalog entry behind a socket.
func socketProvider(h windows.Handle) string {
	var info windows.WSAProtocolInfo
	size := int32(unsafe.Sizeof(info))
	if err := windows.Getsockopt(h, windows.SOL_SOCKET, soProtocolInfoW, (*byte)(unsafe.Pointer(&info)), &size); err != nil {
		return "error " + err.Error()
	}
	return fmt.Sprintf("%s (catalog %d, family %d, type %d, protocol %d, chain %d, flags1 %#x)", windows.UTF16ToString(info.ProtocolName[:]),
		info.CatalogEntryId, info.AddressFamily, info.SocketType, info.Protocol, info.ProtocolChain.ChainLen, info.ServiceFlags1)
}

// logExplicitProtocolProvider records which catalog entry an explicit
// protocol number would select, beside the default one the engine uses.
func logExplicitProtocolProvider(t *testing.T, v6 bool, kind, protocol int32) {
	t.Helper()
	family := int32(windows.AF_INET)
	if v6 {
		family = windows.AF_INET6
	}
	h, err := windows.WSASocket(family, kind, protocol, nil, 0, windows.WSA_FLAG_OVERLAPPED|windows.WSA_FLAG_NO_HANDLE_INHERIT)
	if err != nil {
		t.Logf("explicit protocol %d socket: %v", protocol, err)
		return
	}
	owner := winhandle.Open(h, "explicit protocol provider probe open")
	t.Logf("explicit protocol %d selects %s", protocol, socketProvider(owner.Handle("explicit protocol provider probe")))
	owner.SocketClose("explicit protocol provider probe close")
}

func logProtocolCatalog(t *testing.T) {
	t.Helper()
	entries := make([]windows.WSAProtocolInfo, 64)
	size := uint32(len(entries)) * uint32(unsafe.Sizeof(entries[0]))
	n, err := windows.WSAEnumProtocols(nil, &entries[0], &size)
	if err != nil {
		t.Logf("WSAEnumProtocols: %v", err)
		return
	}
	for _, entry := range entries[:n] {
		t.Logf("catalog %d: %s family=%d type=%d protocol=%d chain=%d flags1=%#x providerFlags=%#x",
			entry.CatalogEntryId, windows.UTF16ToString(entry.ProtocolName[:]), entry.AddressFamily, entry.SocketType,
			entry.Protocol, entry.ProtocolChain.ChainLen, entry.ServiceFlags1, entry.ProviderFlags)
	}
}

func goProvider(t *testing.T, conn syscall.Conn) string {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var provider string
	if err := raw.Control(func(fd uintptr) { provider = socketProvider(windows.Handle(fd)) }); err != nil {
		t.Fatal(err)
	}
	return provider
}

func lineOptions(v6 bool) []socketOption {
	options := []socketOption{{"SO_TYPE", windows.SOL_SOCKET, 0x1008}, {"SO_REUSEADDR", windows.SOL_SOCKET, windows.SO_REUSEADDR},
		{"SO_EXCLUSIVEADDRUSE", windows.SOL_SOCKET, ^windows.SO_REUSEADDR}}
	if v6 {
		return append(options, socketOption{"IPV6_UNICAST_IF", windows.IPPROTO_IPV6, ipUnicastIf}, socketOption{"IPV6_V6ONLY", windows.IPPROTO_IPV6, windows.IPV6_V6ONLY})
	}
	return append(options, socketOption{"IP_UNICAST_IF", windows.IPPROTO_IP, ipUnicastIf})
}

// The engine's native TCP sockets must leave Windows with the same socket as
// the Go dial path they replace, which health probes still use: the same line
// options, bind and connected options, read back from the kernel.
func TestNativeTCPMatchesGoDialOptions(t *testing.T) {
	hosted(t)
	logProtocolCatalog(t)
	pool := completionTestPool(t, queryTCPCompletionPolicy(windows.WSAEnumProtocols))
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			v6 := network == "tcp6"
			listener, err := net.ListenTCP(network, &net.TCPAddr{IP: loopbackSource(v6).AsSlice()})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			native, nativePeer := dialNative(t, pool, listener)
			defer native.Close()
			defer nativePeer.Close()
			line := loopbackLine(t)
			dialer := net.Dialer{Timeout: tcpDialTimeout, LocalAddr: &net.TCPAddr{IP: loopbackSource(v6).AsSlice()},
				Control: bindSocket(line, v6), KeepAlive: 30 * time.Second}
			conn, err := dialer.Dial(network, listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			goPeer, err := listener.AcceptTCP()
			if err != nil {
				t.Fatal(err)
			}
			defer goPeer.Close()
			options := append(lineOptions(v6), socketOption{"SO_REUSE_UNICASTPORT", windows.SOL_SOCKET, soReuseUnicastPort},
				socketOption{"TCP_NODELAY", windows.IPPROTO_TCP, windows.TCP_NODELAY}, socketOption{"SO_KEEPALIVE", windows.SOL_SOCKET, windows.SO_KEEPALIVE},
				socketOption{"TCP_KEEPIDLE", windows.IPPROTO_TCP, windows.TCP_KEEPIDLE}, socketOption{"TCP_KEEPINTVL", windows.IPPROTO_TCP, windows.TCP_KEEPINTVL},
				socketOption{"TCP_KEEPCNT", windows.IPPROTO_TCP, windows.TCP_KEEPCNT})
			got := readOptions(native.handle.Handle("TCP option parity"), options)
			want := goOptions(t, conn.(*net.TCPConn), options)
			got["provider"] = socketProvider(native.handle.Handle("TCP provider parity"))
			want["provider"] = goProvider(t, conn.(*net.TCPConn))
			options = append(options, socketOption{name: "provider"})
			logExplicitProtocolProvider(t, v6, windows.SOCK_STREAM, windows.IPPROTO_TCP)
			index := line.Index4
			if v6 {
				index = line.Index6
			}
			t.Logf("native=%v go=%v interface=%d", got, want, index)
			for _, option := range options {
				if got[option.name] != want[option.name] {
					t.Errorf("%s: native %s, Go dial path %s", option.name, got[option.name], want[option.name])
				}
			}
			if strings.HasPrefix(got["TCP_NODELAY"], "error") || got["TCP_NODELAY"] == "0" || got["SO_KEEPALIVE"] == "0" {
				t.Errorf("connected options missing: %v", got)
			}
			bound := native.local.(*net.TCPAddr).AddrPort()
			if bound.Addr() != loopbackSource(v6) || bound.Port() == 0 || native.remote.(*net.TCPAddr).AddrPort() != unmapped(listener.Addr().(*net.TCPAddr).AddrPort()) {
				t.Fatalf("native endpoints: local=%s remote=%s listener=%s", native.local, native.remote, listener.Addr())
			}
		})
	}
}

// The same for the NAT's datagram sockets, plus Go's disabled ICMP receive
// errors: a port unreachable must not fail the next receive.
func TestNativeUDPMatchesGoListenOptions(t *testing.T) {
	hosted(t)
	for _, v6 := range []bool{false, true} {
		network := map[bool]string{false: "udp4", true: "udp6"}[v6]
		t.Run(network, func(t *testing.T) {
			native := openNativeUDP(t, nil, v6)
			defer native.Close()
			config := net.ListenConfig{Control: bindSocket(loopbackLine(t), v6)}
			packet, err := config.ListenPacket(context.Background(), network, netip.AddrPortFrom(loopbackSource(v6), 0).String())
			if err != nil {
				t.Fatal(err)
			}
			conn := packet.(*net.UDPConn)
			defer conn.Close()
			options := append(lineOptions(v6), socketOption{"SO_BROADCAST", windows.SOL_SOCKET, windows.SO_BROADCAST})
			got := readOptions(native.handle.Handle("UDP option parity"), options)
			want := goOptions(t, conn, options)
			got["provider"] = socketProvider(native.handle.Handle("UDP provider parity"))
			want["provider"] = goProvider(t, conn)
			options = append(options, socketOption{name: "provider"})
			logExplicitProtocolProvider(t, v6, windows.SOCK_DGRAM, windows.IPPROTO_UDP)
			t.Logf("native=%v go=%v", got, want)
			for _, option := range options {
				if got[option.name] != want[option.name] {
					t.Errorf("%s: native %s, Go listen path %s", option.name, got[option.name], want[option.name])
				}
			}
			if native.local.Addr() != loopbackSource(v6) || native.local.Port() == 0 {
				t.Fatalf("native bind: %s", native.local)
			}
			closed, err := net.ListenUDP(network, &net.UDPAddr{IP: loopbackSource(v6).AsSlice()})
			if err != nil {
				t.Fatal(err)
			}
			unreachable := unmapped(closed.LocalAddr().(*net.UDPAddr).AddrPort())
			closed.Close()
			if _, err := native.WriteTo([]byte("no listener"), unreachable, false); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.WriteToUDPAddrPort([]byte("no listener"), unreachable); err != nil {
				t.Fatal(err)
			}
			time.Sleep(200 * time.Millisecond) // the loopback port unreachable has arrived
			var b [64]byte
			native.mu.Lock()
			_, _, nativeErr := native.receive(b[:], "UDP ICMP parity receive")
			native.mu.Unlock()
			conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			_, _, goErr := conn.ReadFromUDPAddrPort(b[:])
			t.Logf("after port unreachable: native=%v go=%v", nativeErr, goErr)
			if !errors.Is(nativeErr, platform.ErrWouldBlock) || !errors.Is(goErr, windows.WSAETIMEDOUT) && !errors.Is(goErr, context.DeadlineExceeded) && !isTimeout(goErr) {
				t.Fatalf("an ICMP port unreachable reached a receive: native=%v go=%v", nativeErr, goErr)
			}
		})
	}
}

func isTimeout(err error) bool {
	var timeout interface{ Timeout() bool }
	return errors.As(err, &timeout) && timeout.Timeout()
}

// ConnectEx's completion carries an NTSTATUS; the dial must report it as the
// Winsock error the port-limit diagnostics recognize, and leave no registration.
func TestNativeTCPDialRefusalIsWinsockError(t *testing.T) {
	hosted(t)
	pool := completionTestPool(t, tcpCompletionPolicy{reason: "non-ifs-provider"})
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	closed := unmapped(listener.Addr().(*net.TCPAddr).AddrPort())
	listener.Close()
	started := time.Now()
	c, err := pool.dial(context.Background(), loopbackLine(t), loopbackSource(false), closed)
	t.Logf("refused after %s: %v; stats %v", time.Since(started), err, pool.stats())
	if c != nil || !errors.Is(err, windows.WSAECONNREFUSED) {
		t.Fatalf("closed loopback port: socket=%v err=%v", c, err)
	}
	var op *net.OpError
	if !errors.As(err, &op) || op.Op != "dial" || op.Net != "tcp4" || !strings.Contains(err.Error(), "connectex") {
		t.Fatalf("refusal lost its dial context: %#v", err)
	}
	if stats := pool.stats(); stats["sockets"] != 0 || stats["connectingSockets"] != 0 {
		t.Fatalf("refused dial left a registration: %v", stats)
	}
}

// A dial abandoned mid-ConnectEx must cancel, drain the packet and only then
// close; a deadline is reported as a timeout.
func TestNativeTCPDialCancelDrainsConnectEx(t *testing.T) {
	hosted(t)
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "deadline"}[deadline], func(t *testing.T) {
			pool := completionTestPool(t, tcpCompletionPolicy{reason: "non-ifs-provider"})
			var cancels atomic.Int32
			pool.cancel = func(h windows.Handle, op *windows.Overlapped) error {
				cancels.Add(1)
				return windows.CancelIoEx(h, op)
			}
			listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			closed := unmapped(listener.Addr().(*net.TCPAddr).AddrPort())
			listener.Close()
			// Windows retries a refused loopback SYN for about two seconds, so
			// ConnectEx is genuinely pending when the dial is abandoned.
			ctx, cancel := context.WithCancel(context.Background())
			if deadline {
				ctx, cancel = context.WithTimeout(context.Background(), 300*time.Millisecond)
			}
			defer cancel()
			line := loopbackLine(t)
			packets := pool.completed.Load() // this fresh pool's only socket is the one below
			done := make(chan error, 1)
			go func() {
				c, err := pool.dial(ctx, line, loopbackSource(false), closed)
				if c != nil {
					c.Close()
				}
				done <- err
			}()
			for start := time.Now(); pool.pendingConn.Load() == 0; time.Sleep(time.Millisecond) {
				if time.Since(start) > 5*time.Second {
					t.Fatal("ConnectEx never went pending")
				}
			}
			if stats := pool.stats(); stats["connectingSockets"] != 1 {
				t.Fatalf("pending connect not registered: %v", stats)
			}
			if !deadline {
				cancel()
			}
			var dialErr error
			select {
			case dialErr = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("abandoned dial did not return")
			}
			t.Logf("abandoned dial: %v; stats %v", dialErr, pool.stats())
			want := context.Canceled
			if deadline {
				want = context.DeadlineExceeded
			}
			if !errors.Is(dialErr, want) || deadline && !isTimeout(dialErr) {
				t.Fatalf("abandoned dial error: %v", dialErr)
			}
			if cancels.Load() != 1 || pool.completed.Load() != packets+1 {
				t.Fatalf("ConnectEx was not cancelled and drained: cancels=%d packets=%d->%d", cancels.Load(), packets, pool.completed.Load())
			}
			if stats := pool.stats(); stats["sockets"] != 0 || stats["connectingSockets"] != 0 {
				t.Fatalf("abandoned dial left a registration: %v", stats)
			}
		})
	}
}

// Without either readiness backend, a native socket keeps its type and
// binding through GC, carries payload and FIN (TCP) or exact datagrams with
// their source (UDP), and its generation ends at Close. This is the property
// the old copies lost.
func TestNativeSocketsKeepEndpointWithoutReadiness(t *testing.T) {
	hosted(t)
	pool := completionTestPool(t, queryTCPCompletionPolicy(windows.WSAEnumProtocols))
	for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			v6 := network[len(network)-1] == '6'
			ip := loopbackSource(v6).AsSlice()
			var listener *net.TCPListener
			var receiver *net.UDPConn
			var err error
			if network[:3] == "tcp" {
				listener, err = net.ListenTCP(network, &net.TCPAddr{IP: ip})
			} else {
				receiver, err = net.ListenUDP(network, &net.UDPAddr{IP: ip})
			}
			if err != nil {
				t.Fatal(err)
			}
			if listener != nil {
				defer listener.Close()
			} else {
				defer receiver.Close()
			}
			// Normal FIN rows remain in TIME_WAIT. Keep this small enough for the
			// later, mandatory 2,000-row owner timing fixture.
			for round := range 128 {
				func() {
					var owner winhandle.Owner
					var local netip.AddrPort
					var closeSocket func() error
					var peer *net.TCPConn
					var datagram *udpSocket
					kind := windows.SOCK_DGRAM
					if listener != nil {
						kind = windows.SOCK_STREAM
						c, accepted := dialNative(t, pool, listener)
						defer accepted.Close()
						owner, local, closeSocket, peer = c.handle, c.local.(*net.TCPAddr).AddrPort(), c.Close, accepted
					} else {
						datagram = openNativeUDP(t, nil, v6)
						owner, local, closeSocket = datagram.handle, datagram.local, datagram.Close
					}
					closed := false
					defer func() {
						if !closed {
							closeSocket()
						}
					}()
					check := func(stage string) {
						t.Helper()
						h := owner.Handle("native endpoint " + stage)
						gotKind, kindErr := windows.GetsockoptInt(h, windows.SOL_SOCKET, 0x1008)
						name, nameErr := localName(h)
						if kindErr != nil || gotKind != kind || nameErr != nil || name != local {
							t.Fatalf("round=%d stage=%s type=%d/%d %v name=%s want=%s %v", round, stage, gotKind, kind, kindErr, name, local, nameErr)
						}
					}
					check("created")
					if round%32 == 0 {
						runtime.GC()
						check("GC completed")
					}
					payload := []byte(fmt.Sprintf("native endpoint %d", round))
					if peer != nil {
						if n, err := socketIO(owner, "send", payload); err != nil || n != len(payload) {
							t.Fatalf("round=%d native send=%d/%d: %v", round, n, len(payload), err)
						}
						if err := windows.Shutdown(owner.Handle("native endpoint shutdown"), windows.SHUT_WR); err != nil {
							t.Fatalf("round=%d native half-close without readiness: %v", round, err)
						}
						peer.SetReadDeadline(time.Now().Add(time.Second))
						got, err := io.ReadAll(peer)
						if err != nil || !bytes.Equal(got, payload) {
							t.Fatalf("round=%d peer payload/FIN %q: %v", round, got, err)
						}
					} else {
						destination := unmapped(receiver.LocalAddr().(*net.UDPAddr).AddrPort())
						datagram.mu.Lock()
						n, err := datagram.send(payload, destination, false, "endpoint test send")
						datagram.mu.Unlock()
						if err != nil || n != len(payload) {
							t.Fatalf("round=%d native datagram=%d/%d: %v", round, n, len(payload), err)
						}
						receiver.SetReadDeadline(time.Now().Add(time.Second))
						var b [64]byte
						n, source, err := receiver.ReadFromUDPAddrPort(b[:])
						if err != nil || !bytes.Equal(b[:n], payload) || unmapped(source) != local {
							t.Fatalf("round=%d datagram %q from %s (want %s): %v", round, b[:n], source, local, err)
						}
					}
					check("payload sent")
					closed = true
					if err := closeSocket(); err != nil {
						t.Fatal(err)
					}
					if winhandle.Enabled {
						func() {
							defer func() {
								if failure := recover(); failure == nil || !strings.Contains(fmt.Sprint(failure), "ended or replaced generation") {
									t.Fatalf("closed generation was not rejected before a syscall: %v", failure)
								}
							}()
							owner.Handle("native endpoint closed generation negative control")
						}()
					}
				}()
			}
			t.Log("128 native sockets kept type and binding through GC; payload and FIN or datagram source verified; each generation ended at Close")
		})
	}
}
