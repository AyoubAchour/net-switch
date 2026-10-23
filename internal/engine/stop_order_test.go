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

type retiringTun struct {
	*testfake.Tun
	begun, joined bool
}

func (t *retiringTun) BeginClose()  { t.begun = true }
func (t *retiringTun) Close() error { t.joined = true; return t.Tun.Close() }

type removalAfterJoin struct {
	testfake.Routes
	tun *retiringTun
}

func (r *removalAfterJoin) Cleanup(ctx context.Context) error {
	if !r.tun.begun || !r.tun.joined {
		return errors.New("journal mutation overlapped unretired rings/registrar")
	}
	return r.Routes.Cleanup(ctx)
}
func TestStopJoinsSessionBeforeJournalMutation(t *testing.T) {
	tun := &retiringTun{Tun: testfake.NewTun()}
	routes := &removalAfterJoin{tun: tun}
	e := New(context.Background(), Dependencies{OpenTun: func(context.Context) (platform.TunDevice, error) { return tun, nil }, Routes: routes, Dialer: testfake.Dialer{}, Owners: &testfake.Owners{}}, flows.Defaults(), nil)
	config := policy.Config{Lines: []platform.Line{{ID: "A"}}}
	if _, err := e.Start(context.Background(), policy.Revision{N: 1, Hash: policy.Hash(config), Config: config}); err != nil {
		t.Fatal(err)
	}
	if err := e.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}
