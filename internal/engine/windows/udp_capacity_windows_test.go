//go:build windows

package winengine

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

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
