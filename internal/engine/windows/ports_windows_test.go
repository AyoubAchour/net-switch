//go:build windows

package winengine

import (
	"context"
	"encoding/binary"
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
	variants := []bool{false, true}
	if os.Getenv("NETSWITCH_PORT_BASELINE") == "production" {
		variants = []bool{true}
	}
	for _, reuse := range variants {
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
				ports := map[uint16]bool{}
				for _, socket := range clients {
					ports[uint16(socket.LocalAddr().(*net.TCPAddr).Port)] = true
				}
				for _, socket := range append(clients, peers...) {
					socket.CloseWrite()
				}
				for _, socket := range append(clients, peers...) {
					socket.Close()
				}
				// Do not manufacture free capacity with abortive closes.
				// The next phase starts only after the native table shows that
				// these normally closed tuples, including TIME_WAIT, are gone.
				started := time.Now()
				for {
					states := nativeReleasedStates(t, ports)
					total := 0
					for _, count := range states {
						total += count
					}
					evidence, _ := json.Marshal(map[string]any{"reuseUnicastPort": reuse, "elapsedMS": time.Since(started).Milliseconds(),
						"released": len(ports), "remaining": total, "states": states})
					t.Logf("WINDOWS NATIVE PORT RELEASE %s", evidence)
					if total == 0 {
						break
					}
					if time.Since(started) > 5*time.Minute {
						t.Fatal("native closed ports did not leave the TCP table within five minutes")
					}
					time.Sleep(time.Second)
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

func nativeReleasedStates(t *testing.T, ports map[uint16]bool) map[uint32]int {
	t.Helper()
	b, err := readOwnerTable(context.Background(), tcpTable, windows.AF_INET, tcpOwnerPIDAll)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := ownerRows(b, 4, 24)
	if err != nil {
		t.Fatal(err)
	}
	states := map[uint32]int{}
	for _, row := range rows {
		if [4]byte(row[4:8]) == [4]byte{127, 0, 0, 1} && [4]byte(row[12:16]) == [4]byte{127, 0, 0, 2} &&
			ports[binary.BigEndian.Uint16(row[8:])] {
			states[binary.LittleEndian.Uint32(row)]++
		}
	}
	return states
}
