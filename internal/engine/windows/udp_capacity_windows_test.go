//go:build windows

package winengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestNativeUDPPairedCapacity(t *testing.T) {
	hosted(t)
	if os.Getenv("NETSWITCH_PORT_GATE") != "1" {
		t.Skip("native UDP pair isolation belongs to the hosted capacity fixture")
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
	for _, native := range []bool{false, true} {
		t.Run(map[bool]string{false: "Go", true: "ReadyUDP"}[native], func(t *testing.T) {
			peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 3)})
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
			var engines []*udpSocket
			defer func() {
				for _, app := range apps {
					app.Close()
				}
				for _, engine := range engines {
					engine.Close()
				}
			}()
			wake := make(chan struct{}, 1)
			config := net.ListenConfig{Control: bindSocket(Adapter{Index4: index}, false)}
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
			for range 12000 {
				app, err := net.DialUDP("udp4", nil, peer.LocalAddr().(*net.UDPAddr))
				if err != nil {
					limit, phase = err, "app connect"
					break
				}
				packet, err := config.ListenPacket(context.Background(), "udp4", "127.0.0.2:0")
				if err != nil {
					app.Close()
					limit, phase = err, "engine bind"
					break
				}
				conn := packet.(*net.UDPConn)
				raw, err := conn.SyscallConn()
				if err != nil {
					app.Close()
					conn.Close()
					t.Fatal(err)
				}
				engine := &udpSocket{conn: conn, raw: raw, pool: pool, local: conn.LocalAddr().(*net.UDPAddr).AddrPort(), mtu: 65535}
				apps, engines = append(apps, app), append(engines, engine)
				ports[uint16(app.LocalAddr().(*net.UDPAddr).Port)] = true
				ports[engine.local.Port()] = true
				var watch *udpWatch
				if native {
					value, err := engine.Watch(func() { wake <- struct{}{} })
					if err != nil {
						t.Fatal(err)
					}
					watch = value.(*udpWatch)
				}
				if _, err := app.Write(payload); err != nil {
					t.Fatal(err)
				}
				echo()
				app.SetReadDeadline(time.Now().Add(2 * time.Second))
				if n, err := app.Read(received[:]); err != nil || !bytes.Equal(received[:n], payload) {
					t.Fatalf("native app receive: %d %v", n, err)
				}
				destination := peer.LocalAddr().(*net.UDPAddr).AddrPort()
				if native {
					if err := watch.Arm(true, false); err != nil {
						t.Fatal(err)
					}
					if _, err := engine.TryWriteTo(payload, destination, false); err != nil {
						t.Fatal(err)
					}
				} else if _, err := engine.WriteTo(payload, destination, false); err != nil {
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
					engine.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
					n, source, err := engine.ReadFrom(received[:])
					if err != nil || source != destination || !bytes.Equal(received[:n], payload) {
						t.Fatalf("Go engine receive: %d %s %v", n, source, err)
					}
				}
			}
			if !portLimit(limit) {
				t.Fatalf("native pair limit was not established: %v", limit)
			}
			memory, memoryErr := processMemory()
			evidence, _ := json.Marshal(map[string]any{"readyUDP": native, "heldPairs": len(apps),
				"uniquePorts": len(ports), "echoedDatagrams": len(apps) * 2, "phase": phase,
				"error": limit.Error(), "processMemory": memory, "memoryError": memoryErr})
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
