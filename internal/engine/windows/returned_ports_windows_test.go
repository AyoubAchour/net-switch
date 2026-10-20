//go:build windows

package winengine

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"

	"golang.org/x/sys/windows"
)

type nativeBindHandle struct{ handle windows.Handle }

func (h nativeBindHandle) Control(fn func(uintptr)) error { fn(uintptr(h.handle)); return nil }
func (nativeBindHandle) Read(func(uintptr) bool) error    { return errors.New("unused native probe read") }
func (nativeBindHandle) Write(func(uintptr) bool) error {
	return errors.New("unused native probe write")
}

func TestReturnedPortsBindWithoutReuse(t *testing.T) {
	hosted(t)
	input := os.Getenv("NETSWITCH_RETURNED_PORTS")
	if input == "" {
		t.Skip("capacity recovery supplies the measured returned ports")
	}
	var groups []struct {
		Source string   `json:"source"`
		Ports  []uint16 `json:"ports"`
	}
	if err := json.Unmarshal([]byte(input), &groups); err != nil {
		t.Fatal(err)
	}
	var handles []windows.Handle
	var occupied []tcpStateGroup
	bound, checked := 0, 0
	defer func() {
		for _, h := range handles {
			// These sockets never connected or carried data. Closing a bare
			// bound descriptor sends neither FIN nor RST and creates no TIME_WAIT.
			windows.Closesocket(h)
		}
	}()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var snapshot []tcpStateGroup
	refresh := func() {
		state := nativeSocketState()
		if err := state["error"]; err != nil {
			t.Fatalf("native state before returned-port bind: %v", err)
		}
		snapshot = state["groups"].([]tcpStateGroup)
	}
	refresh()
	for _, group := range groups {
		source, err := netip.ParseAddr(group.Source)
		if err != nil || !source.Is4() || !netip.MustParsePrefix("198.18.0.0/15").Contains(source) {
			t.Fatal("returned-port probe is restricted to the hosted TUN/TestISP addresses")
		}
		var index uint32
		for _, iface := range interfaces {
			addresses, err := iface.Addrs()
			if err != nil {
				t.Fatal(err)
			}
			for _, address := range addresses {
				prefix, err := netip.ParsePrefix(address.String())
				if err == nil && prefix.Addr() == source {
					index = uint32(iface.Index)
				}
			}
		}
		if index == 0 {
			t.Fatalf("source interface missing: %s", source)
		}
		for _, port := range group.Ports {
			checked++
			// TIME_WAIT disappearance releases our old tuple. Another process
			// can then claim that port before this probe runs. Record its native
			// row; only an unoccupied port is an available bind opportunity.
			otherOwner := func() bool {
				for _, row := range snapshot {
					if !slices.Contains(row.Ports, port) {
						continue
					}
					if row.Source == group.Source && row.Destination == "198.19.128.2" &&
						row.RemotePort >= 25000 && row.RemotePort <= 25007 {
						t.Fatalf("released fixture tuple still exists: %+v", row)
					}
					row.Ports = []uint16{port}
					occupied = append(occupied, row)
					return true
				}
				return false
			}
			if otherOwner() {
				continue
			}
			h, err := windows.Socket(windows.AF_INET, windows.SOCK_STREAM, windows.IPPROTO_TCP)
			if err != nil {
				t.Fatal(err)
			}
			handles = append(handles, h)
			if err := bindSocket(Adapter{Index4: index}, false)("tcp4", "", nativeBindHandle{h}); err != nil {
				t.Fatal(err)
			}
			// Do not use address reuse to bypass a live or TIME_WAIT owner.
			if err := windows.SetsockoptInt(h, windows.SOL_SOCKET, 0x3007, 0); err != nil { // SO_REUSE_UNICASTPORT.
				t.Fatal(err)
			}
			if err := windows.SetsockoptInt(h, windows.SOL_SOCKET, ^windows.SO_REUSEADDR, 1); err != nil { // SO_EXCLUSIVEADDRUSE.
				t.Fatal(err)
			}
			if err := windows.Bind(h, &windows.SockaddrInet4{Addr: source.As4(), Port: int(port)}); err != nil {
				refresh() // Observe a racing allocation; never retry this bind.
				if (errors.Is(err, windows.WSAEADDRINUSE) || errors.Is(err, windows.WSAEACCES)) && otherOwner() {
					continue
				}
				t.Fatalf("returned port %s:%d is not bindable: %v", source, port, err)
			}
			bound++
		}
	}
	if checked != 1024 || bound+len(occupied) != checked {
		t.Fatalf("expected every one of 512 app and 512 engine ports accounted, checked=%d bound=%d occupied=%d", checked, bound, len(occupied))
	}
	evidence, _ := json.Marshal(map[string]any{"checked": checked, "bound": bound, "reoccupied": occupied,
		"oldAll1024BindCheckWouldPass": bound == checked})
	t.Logf("WINDOWS RETURNED PORT BIND %s", evidence)
	t.Logf("all %d currently available ports bound concurrently through their source interfaces, without connecting, retries or abortive close", bound)
}
