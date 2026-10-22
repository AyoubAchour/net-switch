//go:build windows

package winengine

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestNativeEchoReplyPayload(t *testing.T) {
	hosted(t)
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
		t.Fatal("no native loopback interface")
	}
	// Only the ICMP API and reply decoding are under test here. A private
	// binding avoids adding any adapter, address or route to the runner.
	bindings := bindingTable{"echo-fixture": {
		Up: true, Default4: true, Default6: true, Index4: index, Index6: index,
		Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")},
	}}
	routes := &Routes{}
	routes.bindings.Store(&bindings)
	dialer := &Dialer{Routes: routes}
	for _, destination := range bindings["echo-fixture"].Addresses {
		for _, size := range []int{0, 1, 32, 1400, 8992} {
			t.Run(fmt.Sprintf("%s/%d", destination, size), func(t *testing.T) {
				request := make([]byte, 8+size)
				request[0], request[4], request[6] = 8, 17, 39
				if destination.Is6() {
					request[0] = 128
				}
				for i := 8; i < len(request); i++ {
					request[i] = byte(i*53 + 7)
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				reply, err := dialer.Echo(ctx, "echo-fixture", destination, request)
				if err != nil {
					t.Fatal(err)
				}
				wantType := byte(0)
				if destination.Is6() {
					wantType = 129
				}
				if len(reply) != len(request) || reply[0] != wantType || !bytes.Equal(reply[4:], request[4:]) {
					t.Fatalf("echo reply mismatch: size=%d want=%d reply=%x", len(reply), len(request), reply)
				}
			})
		}
	}
}
