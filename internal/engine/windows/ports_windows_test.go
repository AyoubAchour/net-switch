//go:build windows

package winengine

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// This measures Winsock alone, without an app-side proxy socket. It changes no
// machine settings and is separate from the mandatory real-engine flow cap.
func TestNativeBoundPortCapacity(t *testing.T) {
	hosted(t)
	if os.Getenv("NETSWITCH_PORT_GATE") != "1" {
		t.Skip("native port isolation runs in its own focused job")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var index uint32
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			index = uint32(iface.Index)
			break
		}
	}
	if index == 0 {
		t.Fatal("no loopback interface")
	}
	for _, reuse := range []bool{false, true} {
		func() {
			var mu sync.Mutex
			var peers, clients []*net.TCPConn
			var listeners []*net.TCPListener
			var acceptors sync.WaitGroup
			defer func() {
				for _, listener := range listeners {
					listener.Close()
				}
				acceptors.Wait()
				for _, socket := range append(clients, peers...) {
					socket.SetLinger(0)
					socket.Close()
				}
			}()
			for range 8 {
				listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)})
				if err != nil {
					t.Fatal(err)
				}
				listeners = append(listeners, listener)
				acceptors.Go(func() {
					for {
						peer, err := listener.AcceptTCP()
						if err != nil {
							return
						}
						mu.Lock()
						peers = append(peers, peer)
						mu.Unlock()
					}
				})
			}
			control := bindSocket(Adapter{Index4: index}, false)
			if !reuse {
				productionControl := control
				control = func(network, address string, raw syscall.RawConn) error {
					if err := productionControl(network, address, raw); err != nil {
						return err
					}
					var optionErr error
					err := raw.Control(func(fd uintptr) {
						optionErr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, 0x3007, 0)
					})
					if err != nil {
						return err
					}
					return optionErr
				}
			}
			dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, Control: control, Timeout: 5 * time.Second}
			failures := map[string]int{}
			for batch := 0; batch < 65536 && len(failures) == 0; batch += 32 {
				var workers sync.WaitGroup
				for n := range 32 {
					remote := listeners[n%len(listeners)].Addr().String()
					workers.Go(func() {
						conn, err := dialer.DialContext(context.Background(), "tcp4", remote)
						mu.Lock()
						defer mu.Unlock()
						if err != nil {
							failures[err.Error()]++
							return
						}
						clients = append(clients, conn.(*net.TCPConn))
					})
				}
				workers.Wait()
			}
			deadline := time.Now().Add(5 * time.Second)
			var accepted int
			for {
				mu.Lock()
				accepted = len(peers)
				mu.Unlock()
				if accepted == len(clients) || time.Now().After(deadline) {
					break
				}
				time.Sleep(time.Millisecond)
			}
			ports := map[int]bool{}
			for _, client := range clients {
				source := client.LocalAddr().(*net.TCPAddr)
				if !source.IP.Equal(net.IPv4(127, 0, 0, 1)) {
					t.Fatalf("native probe escaped its source binding: %s", source)
				}
				ports[source.Port] = true
			}
			rawRows, timeWait := nativeTCPRowCounts(t)
			evidence, _ := json.Marshal(map[string]any{"reuseUnicastPort": reuse, "connected": len(clients),
				"accepted": accepted, "uniqueSourcePorts": len(ports), "rawRows": rawRows, "timeWait": timeWait,
				"interfaceIndex": index, "source": "127.0.0.1", "peers": len(listeners), "failures": failures})
			t.Logf("WINDOWS NATIVE PORT CAPACITY %s", evidence)
			if len(clients) == 0 || accepted != len(clients) {
				t.Fatal("native capacity precondition failed")
			}
		}()
	}
}
