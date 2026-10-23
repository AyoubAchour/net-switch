package engine

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
)

type healthRoutes struct{ testfake.Routes }

func (*healthRoutes) ForwardingIndex() int { return 9 }

func TestPrivateForwardingChallengeUsesNetstackAndBothPumps(t *testing.T) {
	tun := testfake.NewTun()
	key := bytes.Repeat([]byte{42}, 32)
	e := New(context.Background(), Dependencies{OpenTun: func(context.Context) (platform.TunDevice, error) { return tun, nil }, Routes: &healthRoutes{}, Dialer: testfake.Dialer{}, Owners: &testfake.Owners{}, HealthKey: key}, flows.Defaults(), nil)
	defer e.Stop(context.Background())
	config := policy.Config{Lines: []platform.Line{{ID: "down"}}}
	if _, err := e.Start(context.Background(), policy.Revision{N: 1, Hash: policy.Hash(config), Config: config}); err != nil {
		t.Fatal(err)
	}
	index, port := e.ForwardingCheck()
	if index != 9 || port == 0 {
		t.Fatal(index, port)
	}
	source := netip.MustParseAddrPort("198.18.0.1:32768")
	target := netip.AddrPortFrom(netip.MustParseAddr("198.18.0.2"), port)
	// A reachable endpoint without the private key must not qualify as health.
	tun.In <- packet.UDP(source, target, make([]byte, 40))
	want := append(append([]byte(nil), key...), []byte("nonce123")...)
	tun.In <- packet.UDP(source, target, want)
	select {
	case got := <-tun.Out:
		if len(got) != 68 || !bytes.Equal(got[28:], want) {
			t.Fatalf("wrong private echo: %x", got)
		}
	case <-time.After(time.Second):
		t.Fatal("private packet did not traverse read pump, netstack and write pump")
	}
}
