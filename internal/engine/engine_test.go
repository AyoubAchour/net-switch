package engine

import (
	"context"
	"errors"
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

type preparedRoutes struct {
	testfake.Routes
	lines []platform.Line
}

func (r *preparedRoutes) Prepare(ctx context.Context, lines []platform.Line) error {
	r.lines = append([]platform.Line(nil), lines...)
	return r.Routes.Prepare(ctx, lines)
}

type failSecondSave struct{ count int }

func (s *failSecondSave) SaveApplied(policy.Applied) error {
	s.count++
	if s.count == 2 {
		return errors.New("state fsync failed")
	}
	return nil
}
func TestApplyRestoresRoutesOnPersistenceFailure(t *testing.T) {
	routes := &preparedRoutes{}
	e := New(context.Background(), Dependencies{OpenTun: func(context.Context) (platform.TunDevice, error) { return testfake.NewTun(), nil }, Routes: routes, Dialer: testfake.Dialer{}, Owners: &testfake.Owners{}}, flows.Defaults(), &failSecondSave{})
	defer e.Stop(context.Background())
	c := policy.Config{Lines: []platform.Line{{ID: "A"}}}
	r := policy.Revision{N: 1, Hash: policy.Hash(c), Config: c}
	if _, err := e.Start(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	r.N = 2
	r.Config.Lines = []platform.Line{{ID: "B"}}
	r.Hash = policy.Hash(r.Config)
	if _, err := e.Apply(context.Background(), r); err == nil {
		t.Fatal("persistence failure acknowledged")
	}
	if routes.lines[0].ID != "A" || e.Table.Applied().N != 1 {
		t.Fatal("route state differs from loaded policy")
	}
}
