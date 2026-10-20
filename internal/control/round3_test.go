package control

import (
	"context"
	"fmt"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/control/engine"
)

type bootFailureEngine struct {
	*fakeEngine
	clock    *fakeClock
	attempts []int64
}

func (e *bootFailureEngine) Start(context.Context, engine.Policy) error {
	e.attempts = append(e.attempts, e.clock.Now().UnixMilli())
	err := fmt.Errorf("boot failure %d", len(e.attempts))
	e.s = engine.Snapshot{Status: "error", FailureID: err.Error()}
	return err
}

func TestSignInPersistsIntentAndCannotAccelerateBootFailures(t *testing.T) {
	c, base, clock, _ := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	c.wanted = false
	e := &bootFailureEngine{fakeEngine: base, clock: clock}
	c.op.Engine = e
	ctx := context.Background()
	if err := c.SignIn(ctx); err != nil {
		t.Fatal(err)
	}
	if len(e.attempts) != 0 || c.op.Journal.Values()["wanted"] != true {
		t.Fatal("sign-in must acknowledge durable intent without attempting a start")
	}
	start := clock.Now().UnixMilli()
	for ms := int64(0); ms <= 40000; ms += 100 {
		if ms > 0 {
			clock.advance(100)
		}
		// Both a retrying desktop and another owner session are untrusted
		// scheduling inputs; neither can move the supervisor's deadline.
		if err := c.SignIn(ctx); err != nil {
			t.Fatal(err)
		}
		_ = c.Supervise(ctx)
	}
	want := []int64{0, 1000, 3000, 8000, 38000}
	if len(e.attempts) != len(want) {
		t.Fatalf("attempts=%v", e.attempts)
	}
	for i, at := range e.attempts {
		if at-start != want[i] {
			t.Fatalf("attempt %d at %dms, want %dms", i+1, at-start, want[i])
		}
	}
	if len(c.failureTimes) != 5 {
		t.Fatalf("failure count=%d", len(c.failureTimes))
	}
}

func TestRepeatedLeaseStopsRecoverWithoutFailureBudget(t *testing.T) {
	c, e, _, _ := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	for cycle := range 7 {
		e.s = engine.Snapshot{Status: "off"} // verified lease-expired exit from Remote
		if err := c.Supervise(context.Background()); err != nil {
			t.Fatal(err)
		}
		if e.Snapshot().Status != "on" || len(c.failureTimes) != 0 || !c.wanted {
			t.Fatalf("standby cycle %d did not recover without latching", cycle)
		}
	}
}
