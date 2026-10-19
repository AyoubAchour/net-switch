package engine

import (
	"context"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
)

func TestStartRollbackAndDisconnectLifetime(t *testing.T) {
	for _, fail := range []string{"prepare", "capture", ""} {
		t.Run(fail, func(t *testing.T) {
			tun := testfake.NewTun()
			routes := &testfake.Routes{Fail: fail}
			e := New(context.Background(), Dependencies{OpenTun: func(context.Context) (platform.TunDevice, error) { return tun, nil }, Routes: routes, Dialer: testfake.Dialer{}, Owners: &testfake.Owners{}}, flows.Defaults(), nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := policy.Config{Lines: []platform.Line{{ID: "A"}}}
			_, err := e.Start(ctx, policy.Revision{N: 1, Hash: policy.Hash(c), Config: c})
			if fail != "" {
				if err == nil || e.Table.Applied() != nil || routes.Calls[len(routes.Calls)-1] != "cleanup" {
					t.Fatal("start failure did not roll back")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			cancel()
			if e.Table.Applied() == nil {
				t.Fatal("controller disconnect stopped routing")
			}
			if routes.Calls[len(routes.Calls)-1] != "capture" {
				t.Fatal("capture was not last")
			}
			if err := e.Stop(context.Background()); err != nil {
				t.Fatal(err)
			}
			if e.Table.Applied() != nil {
				t.Fatal("stop kept loaded revision")
			}
		})
	}
}
