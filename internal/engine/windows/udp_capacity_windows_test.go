//go:build windows

package winengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// udpPairBinding returns the matched baseline's interface index, engine source
// and peer address: loopback unless the hosted fixture names the actual
// TestISP source and interface.
func udpPairBinding(t *testing.T) (uint32, string, net.IP) {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var index uint32
	source, peerSource := "127.0.0.2", net.IPv4(127, 0, 0, 3)
	for _, item := range interfaces {
		if item.Flags&net.FlagLoopback != 0 {
			index = uint32(item.Index)
			break
		}
	}
	if index == 0 {
		t.Fatal("no loopback interface")
	}
	if configured := os.Getenv("NETSWITCH_UDP_BASELINE_SOURCE"); configured != "" {
		value, err := strconv.ParseUint(os.Getenv("NETSWITCH_UDP_BASELINE_INDEX"), 10, 32)
		if err != nil || value == 0 || net.ParseIP(configured).To4() == nil {
			t.Fatalf("invalid matched UDP baseline binding: %q %d %v", configured, value, err)
		}
		iface, err := net.InterfaceByIndex(int(value))
		if err != nil {
			t.Fatal(err)
		}
		addresses, err := iface.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		matches := false
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			matches = matches || (err == nil && ip.Equal(net.ParseIP(configured)))
		}
		if !matches {
			t.Fatal("matched baseline source is not on the specified interface")
		}
		index, source, peerSource = uint32(value), configured, net.ParseIP(configured)
	}
	return index, source, peerSource
}

// udpEngineHalves opens the engine half of each pair, bound to the line's
// source with the line's options: plain Go sockets for the native control, or
// the engine's own native constructor plus readiness registration, as
// production sessions are.
type udpEngineHalves struct {
	ready bool
	// unwatched leaves the engine's native socket out of readiness
	// registration (WSAEventSelect), to tell the constructor apart from the
	// registration when one of them changes Windows' refusal rate.
	unwatched bool
	// completionPort additionally attaches each unwatched native socket to
	// an I/O completion port with Go's notification modes, the one remaining
	// difference from a Go-created socket.
	completionPort windows.Handle
	// custom, when set, opens every engine half instead (the option matrix);
	// label names it in the evidence.
	custom func() (io.Closer, error)
	// app, when set, opens every app half in the recovery cycles instead of
	// an automatic-port DialUDP (the explicit in-range port variants).
	app    func(peer *net.UDPAddr) (*net.UDPConn, error)
	label  string
	line   Adapter
	source netip.Addr
	config net.ListenConfig
	pool   *udpReadiness
}

func newUDPEngineHalves(ready bool, index uint32, source string, pool *udpReadiness) udpEngineHalves {
	line := Adapter{Index4: index}
	return udpEngineHalves{ready: ready, line: line, source: netip.MustParseAddr(source),
		config: net.ListenConfig{Control: bindSocket(line, false)}, pool: pool}
}

func (h udpEngineHalves) openGo() (*net.UDPConn, error) {
	packet, err := h.config.ListenPacket(context.Background(), "udp4", netip.AddrPortFrom(h.source, 0).String())
	if err != nil {
		return nil, err
	}
	return packet.(*net.UDPConn), nil
}

func (h udpEngineHalves) openReady(wake func()) (*udpSocket, *udpWatch, error) {
	s, err := openUDP(h.line, netip.AddrPortFrom(h.source, 0), h.pool)
	if err != nil {
		return nil, nil, err
	}
	if h.unwatched {
		if h.completionPort != 0 {
			handle := s.handle.Handle("UDP control completion port")
			if _, err := windows.CreateIoCompletionPort(handle, h.completionPort, 0, 0); err != nil {
				return nil, nil, errors.Join(err, s.Close())
			}
			if err := windows.SetFileCompletionNotificationModes(handle,
				windows.FILE_SKIP_SET_EVENT_ON_HANDLE|windows.FILE_SKIP_COMPLETION_PORT_ON_SUCCESS); err != nil {
				return nil, nil, errors.Join(err, s.Close())
			}
		}
		return s, nil, nil
	}
	watch, err := s.Watch(wake)
	if err != nil {
		return nil, nil, errors.Join(err, s.Close())
	}
	return s, watch.(*udpWatch), nil
}

func (h udpEngineHalves) open() (io.Closer, error) {
	if h.custom != nil {
		return h.custom()
	}
	if h.ready {
		s, _, err := h.openReady(func() {})
		if err != nil {
			return nil, err
		}
		return s, nil
	}
	conn, err := h.openGo()
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (h udpEngineHalves) kind() string {
	if h.label != "" {
		return h.label
	}
	if h.ready && h.unwatched && h.completionPort != 0 {
		return "engine native constructor, no Watch, on a completion port like Go"
	}
	if h.ready && h.unwatched {
		return "engine native constructor, no Watch"
	}
	if h.ready {
		return "engine native constructor, Watch"
	}
	return "plain Go socket"
}

func TestNativeUDPPairedCapacity(t *testing.T) {
	hosted(t)
	if os.Getenv("NETSWITCH_PORT_GATE") != "1" {
		t.Skip("native UDP pair isolation belongs to the hosted capacity fixture")
	}
	index, source, peerSource := udpPairBinding(t)
	for _, variant := range []string{"Go", "ReadyUDP", "Constructor", "ConstructorIOCP"} {
		native, unwatched := variant != "Go", strings.HasPrefix(variant, "Constructor")
		if unwatched && udpRecoveryCycleCount() == 0 {
			continue // only the recovery control needs this split
		}
		t.Run(variant, func(t *testing.T) {
			peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: peerSource})
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			pool, err := newUDPReadiness(nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := pool.close(); err != nil {
					t.Error(err)
				}
			}()
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
			wake := make(chan struct{}, 1)
			halves := newUDPEngineHalves(native, index, source, pool)
			halves.unwatched = unwatched
			if variant == "ConstructorIOCP" {
				port, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
				if err != nil {
					t.Fatal(err)
				}
				defer windows.CloseHandle(port)
				halves.completionPort = port
			}
			ports := map[uint16]bool{}
			payload := []byte("native UDP pairs")
			var received [64]byte
			echo := func() {
				t.Helper()
				peer.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, source, err := peer.ReadFromUDPAddrPort(received[:])
				if err != nil || !bytes.Equal(received[:n], payload) {
					t.Fatalf("native peer receive: n=%d err=%v", n, err)
				}
				if _, err := peer.WriteToUDPAddrPort(payload, source); err != nil {
					t.Fatal(err)
				}
			}
			var limit error
			var phase string
			options := map[string]int{}
			for range 12000 {
				app, err := net.DialUDP("udp4", nil, peer.LocalAddr().(*net.UDPAddr))
				if err != nil {
					limit, phase = err, "app connect"
					break
				}
				var conn *net.UDPConn
				var engine *udpSocket
				var watch *udpWatch
				var local netip.AddrPort
				if native {
					engine, watch, err = halves.openReady(func() { wake <- struct{}{} })
					if err == nil {
						local = engine.LocalAddr()
					}
				} else if conn, err = halves.openGo(); err == nil {
					local = conn.LocalAddr().(*net.UDPAddr).AddrPort()
				}
				if err != nil {
					app.Close()
					limit, phase = err, "engine bind"
					break
				}
				if len(apps) == 0 {
					read := func(h windows.Handle) error {
						for name, option := range map[string]int{"SO_REUSEADDR": windows.SO_REUSEADDR, "SO_EXCLUSIVEADDRUSE": ^windows.SO_REUSEADDR} {
							value, err := windows.GetsockoptInt(h, windows.SOL_SOCKET, option)
							if err != nil {
								return err
							}
							options[name] = value
						}
						return nil
					}
					var optionErr error
					if native {
						optionErr = read(engine.handle.Handle("UDP pair options"))
					} else if raw, err := conn.SyscallConn(); err != nil {
						optionErr = err
					} else {
						var readErr error
						controlErr := raw.Control(func(fd uintptr) { readErr = read(windows.Handle(fd)) })
						optionErr = errors.Join(controlErr, readErr)
					}
					if optionErr != nil {
						app.Close()
						if native {
							engine.Close()
						} else {
							conn.Close()
						}
						t.Fatalf("matched native socket options: %v", optionErr)
					}
				}
				apps = append(apps, app)
				if native {
					engines = append(engines, engine)
				} else {
					engines = append(engines, conn)
				}
				ports[uint16(app.LocalAddr().(*net.UDPAddr).Port)] = true
				ports[local.Port()] = true
				if _, err := app.Write(payload); err != nil {
					t.Fatal(err)
				}
				echo()
				app.SetReadDeadline(time.Now().Add(2 * time.Second))
				if n, err := app.Read(received[:]); err != nil || !bytes.Equal(received[:n], payload) {
					t.Fatalf("native app receive: %d %v", n, err)
				}
				destination := peer.LocalAddr().(*net.UDPAddr).AddrPort()
				if unwatched {
					// The native socket's own pre-Watch blocking path.
					if _, err := engine.WriteTo(payload, destination, false); err != nil {
						t.Fatal(err)
					}
					echo()
					n, source, err := engine.ReadFrom(received[:])
					if err != nil || source != destination || !bytes.Equal(received[:n], payload) {
						t.Fatalf("unwatched native engine receive: %d %s %v", n, source, err)
					}
					continue
				}
				if native {
					if err := watch.Arm(true, false); err != nil {
						t.Fatal(err)
					}
					if _, err := engine.TryWriteTo(payload, destination, false); err != nil {
						t.Fatal(err)
					}
				} else if _, err := conn.WriteToUDPAddrPort(payload, destination); err != nil {
					t.Fatal(err)
				}
				echo()
				if native {
					udpWake(t, wake)
					n, source, err := engine.TryReadFrom(received[:])
					if err != nil || source != destination || !bytes.Equal(received[:n], payload) {
						udpReceiveDiagnostic(t, engine)
						t.Fatalf("native engine receive: %d %s %v", n, source, err)
					}
				} else {
					conn.SetReadDeadline(time.Now().Add(2 * time.Second))
					n, source, err := conn.ReadFromUDPAddrPort(received[:])
					if err != nil || unmapped(source) != destination || !bytes.Equal(received[:n], payload) {
						t.Fatalf("Go engine receive: %d %s %v", n, source, err)
					}
				}
			}
			if !portLimit(limit) {
				t.Fatalf("native pair limit was not established: %v", limit)
			}
			space := diagnoseUDPPortSpace(context.Background())
			if cycles := udpRecoveryCycleCount(); cycles > 0 {
				nativeUDPRecoveryCycles(t, cycles, halves, &apps, &engines, peer, source, space)
				if !native {
					// The engine's gated cycle runs with the TCP corner held; this
					// is the native control for that condition.
					held, release := holdNativeTCPLoad(t)
					nativeUDPRecoveryCyclesWith(t, cycles, halves, held, &apps, &engines, peer, source, space)
					release()
				}
			}
			memory, memoryErr := processMemory()
			evidence, _ := json.Marshal(map[string]any{"readyUDP": native, "heldPairs": len(apps),
				"uniquePorts": len(ports), "echoedDatagrams": len(apps) * 2, "phase": phase,
				"family": "ipv4", "source": source, "interfaceIndex": index,
				"appBind": "wildcard port zero, connected", "engineBind": "specific source port zero, IP_UNICAST_IF",
				"engineSocket": halves.kind(), "engineOptions": options,
				"portSpace": space.Probe,
				"error":     limit.Error(), "processMemory": memory, "memoryError": errorText(memoryErr)})
			t.Logf("WINDOWS NATIVE UDP PAIRED CAPACITY %s", evidence)
		})
	}
}

func TestNativeUDPSocketCapacity(t *testing.T) {
	hosted(t)
	if os.Getenv("NETSWITCH_PORT_GATE") != "1" {
		t.Skip("native UDP pool isolation belongs to the hosted capacity fixture")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var index uint32
	for _, item := range interfaces {
		if item.Flags&net.FlagLoopback != 0 {
			index = uint32(item.Index)
			break
		}
	}
	if index == 0 {
		t.Fatal("no loopback interface")
	}
	config := net.ListenConfig{Control: bindSocket(Adapter{Index4: index}, false)}
	var held []net.PacketConn
	defer func() {
		for _, socket := range held {
			socket.Close()
		}
	}()
	ports := map[int]bool{}
	failures := map[string]int{}
	for range 20000 {
		socket, err := config.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
		if err != nil {
			if !errors.Is(err, windows.WSAENOBUFS) && !errors.Is(err, windows.WSAEADDRINUSE) {
				t.Fatal(err)
			}
			failures[err.Error()]++
			break
		}
		held = append(held, socket)
		address := socket.LocalAddr().(*net.UDPAddr)
		if !address.IP.Equal(net.IPv4(127, 0, 0, 1)) || ports[address.Port] {
			t.Fatalf("source bind/unique port failed: %s", address)
		}
		ports[address.Port] = true
	}
	evidence, _ := json.Marshal(map[string]any{"held": len(held), "uniquePorts": len(ports),
		"failures": failures, "interfaceIndex": index, "source": "127.0.0.1"})
	t.Logf("WINDOWS NATIVE UDP CAPACITY %s", evidence)
	if len(held) == 0 || len(failures) == 0 {
		t.Fatal("native UDP OS limit was not established")
	}
}
