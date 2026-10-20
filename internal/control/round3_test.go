package control

import (
	"context"
	"fmt"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/control/engine"
)

type bootFailureEngine struct {
	*fakeEngine
	clock        *fakeClock
	attempts     []int64
	duringStart  func()
	afterFailure func()
}

func (e *bootFailureEngine) Start(context.Context, engine.Policy) error {
	if e.duringStart != nil {
		e.duringStart()
	}
	e.attempts = append(e.attempts, e.clock.Now().UnixMilli())
	err := fmt.Errorf("boot failure %d", len(e.attempts))
	e.s = engine.Snapshot{Status: "error", FailureID: err.Error()}
	if e.afterFailure != nil {
		e.afterFailure()
	}
	return err
}

func TestStandbyRecoveryDefersStartsUntilResume(t *testing.T) {
	c, e, _, _ := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	for cycle := range 7 {
		c.SetPowerSuspended(true)
		e.s = engine.Snapshot{Status: "off"} // lease expired while services were throttled
		if err := c.Supervise(context.Background()); err != nil {
			t.Fatal(err)
		}
		if e.Snapshot().Status != "off" {
			t.Fatalf("cycle %d started an engine during standby", cycle)
		}
		c.SetPowerSuspended(false)
		if err := c.Supervise(context.Background()); err != nil {
			t.Fatal(err)
		}
		if e.Snapshot().Status != "on" || len(c.failureTimes) != 0 || !c.wanted {
			t.Fatalf("cycle %d failed to recover without latching", cycle)
		}
	}
}

func TestStandbyRecoveryDoesNotCountInterruptedStart(t *testing.T) {
	c, base, clock, _ := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	e := &bootFailureEngine{fakeEngine: base, clock: clock, duringStart: func() { c.SetPowerSuspended(true); c.SetPowerSuspended(false) }}
	c.op.Engine = e
	e.afterFailure = func() { c.mu.Lock(); defer c.mu.Unlock(); c.statusLocked(e.Snapshot()) }
	if err := c.Start(context.Background()); err == nil {
		t.Fatal("missing interrupted start precondition")
	}
	if len(c.failureTimes) != 0 {
		t.Fatal("a start spanning standby consumed the crash budget")
	}
	e.duringStart = nil
	_ = c.Supervise(context.Background())
	if len(c.failureTimes) != 1 {
		t.Fatal("ordinary awake failure did not count", c.failureTimes)
	}
}

// lostReplyEngine models Remote losing the start reply: Start returns while the
// snapshot still says "starting", and connection recovery publishes the
// attempt's outcome later.
type lostReplyEngine struct {
	*fakeEngine
	starts      int
	duringStart func()
}

func (e *lostReplyEngine) Start(context.Context, engine.Policy) error {
	e.starts++
	if e.duringStart != nil {
		e.duringStart()
	}
	e.publish(engine.Snapshot{Status: "starting"})
	return fmt.Errorf("start reply lost %d", e.starts)
}

func (e *lostReplyEngine) publish(s engine.Snapshot) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.s = s
}

func lostReplyCore(t *testing.T) (*Core, *lostReplyEngine) {
	t.Helper()
	c, base, _, _ := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	e := &lostReplyEngine{fakeEngine: base}
	c.op.Engine = e
	return c, e
}

func standby(c *Core) { c.SetPowerSuspended(true); c.SetPowerSuspended(false) }

func TestStandbyRecoveryDoesNotCountDelayedStartOutcome(t *testing.T) {
	c, e := lostReplyCore(t)
	e.duringStart = func() { standby(c) }
	ctx := context.Background()
	if err := c.Start(ctx); err == nil {
		t.Fatal("missing lost start reply precondition")
	}
	for cycle := range 7 {
		if e.Snapshot().Status != "starting" {
			t.Fatalf("cycle %d: start must return before its outcome is known", cycle)
		}
		e.publish(engine.Snapshot{Status: "error", FailureID: fmt.Sprintf("instance-%d", cycle)})
		_ = c.Supervise(ctx)
		if len(c.failureTimes) != 0 {
			t.Fatalf("cycle %d: delayed outcome of a start spanning standby consumed the crash budget: %v", cycle, c.failureTimes)
		}
		if e.starts != cycle+2 || !c.wanted {
			t.Fatalf("cycle %d: supervisor stopped retrying after %d starts", cycle, e.starts)
		}
	}
}

func TestDelayedAwakeStartFailureCountsAndKeepsBudget(t *testing.T) {
	c, e := lostReplyCore(t)
	c.failureTimes = []int64{c.now() - 1000}
	e.duringStart = func() { standby(c) }
	ctx := context.Background()
	_ = c.Start(ctx)
	e.duringStart = nil
	e.publish(engine.Snapshot{Status: "error", FailureID: "spanned"})
	_ = c.Supervise(ctx) // forgives the spanning attempt and retries while awake
	if len(c.failureTimes) != 1 || e.starts != 2 {
		t.Fatalf("precondition: failures=%v starts=%d", c.failureTimes, e.starts)
	}
	e.publish(engine.Snapshot{Status: "error", FailureID: "awake"})
	_ = c.Supervise(ctx)
	if len(c.failureTimes) != 2 {
		t.Fatal("delayed failure of an awake start did not count", c.failureTimes)
	}
}

func TestRecoveredStartEndsPowerClassification(t *testing.T) {
	c, e := lostReplyCore(t)
	c.failureTimes = []int64{c.now() - 1000}
	e.duringStart = func() { standby(c) }
	ctx := context.Background()
	_ = c.Start(ctx)
	if !c.engineStarting {
		t.Fatal("attempt ended before its outcome was known")
	}
	e.publish(engine.Snapshot{Status: "on", Instance: "recovered", StartedAt: c.op.Clock.Now()})
	if err := c.Supervise(ctx); err != nil {
		t.Fatal(err)
	}
	if c.engineStarting {
		t.Fatal("reattached engine left the start attempt open")
	}
	standby(c) // a later wake while running is not part of the start
	e.publish(engine.Snapshot{Status: "error", FailureID: "crashed-after-recovery"})
	_ = c.Supervise(ctx)
	if len(c.failureTimes) != 2 {
		t.Fatal("awake crash after a recovered start did not count", c.failureTimes)
	}
}

func TestStartAttemptEndsOnlyAtTerminalOutcome(t *testing.T) {
	for _, status := range []string{"on", "off", "error"} {
		t.Run(status, func(t *testing.T) {
			c, e := lostReplyCore(t)
			e.duringStart = func() { standby(c) }
			_ = c.Start(context.Background())
			observe := func(s engine.Snapshot) {
				c.mu.Lock()
				defer c.mu.Unlock()
				c.statusLocked(s)
			}
			observe(engine.Snapshot{Status: "stopping"})
			observe(e.Snapshot())
			// Supervise and Poll sample the engine before taking the state lock;
			// a terminal sample taken before Start returned must not end it.
			outcome := func(id string) engine.Snapshot {
				s := engine.Snapshot{Status: status}
				if status == "error" {
					s.FailureID = id
				}
				return s
			}
			observe(outcome("stale"))
			if !c.engineStarting {
				t.Fatal("non-terminal or stale observation ended the attempt")
			}
			e.publish(outcome("late"))
			observe(e.Snapshot())
			if c.engineStarting {
				t.Fatalf("terminal %q outcome left the attempt open", status)
			}
			if len(c.failureTimes) != 0 {
				t.Fatal("outcome of a start spanning standby counted", c.failureTimes)
			}
		})
	}
}

func TestStandbyRecoveryKeepsGenuineFailures(t *testing.T) {
	c, e, _, _ := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	c.failureTimes = []int64{c.now()}
	c.SetPowerSuspended(true)
	e.s = engine.Snapshot{Status: "error", FailureID: "power-interrupted"}
	if err := c.Supervise(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(c.failureTimes) != 1 {
		t.Fatal("suspend changed the genuine failure budget", c.failureTimes)
	}
	c.SetPowerSuspended(false)
	if err := c.Supervise(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(c.failureTimes) != 1 || e.Snapshot().Status != "on" {
		t.Fatal("resume did not preserve the budget and recover")
	}
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

func TestNewSignInAfterLogoffResetsOldLatchWithoutStarting(t *testing.T) {
	c, e, _, _ := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	c.wanted = false
	c.failureTimes = []int64{1, 2, 3, 4, 5}
	c.retryAt = c.now() + 30000
	e.calls = nil
	if err := c.SignIn(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(c.failureTimes) != 0 || c.retryAt != 0 || !c.wanted {
		t.Fatal("fresh OS sign-in kept the previous intent's latch")
	}
	for _, call := range e.calls {
		if call == "start" {
			t.Fatal("sign-in bypassed supervisor")
		}
	}
}
