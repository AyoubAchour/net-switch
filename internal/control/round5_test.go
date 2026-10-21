package control

import (
	"context"
	"slices"
	"strings"
	"testing"
)

type retryState struct {
	attempts int
	at       int64
	failures []int64
}

func (c *Core) retryStateNow() retryState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return retryState{c.retryAttempts, c.retryAt, append([]int64{}, c.failureTimes...)}
}

func (r retryState) equal(o retryState) bool {
	return r.attempts == o.attempts && r.at == o.at && slices.Equal(r.failures, o.failures)
}

func journalFile(path string) bool { return strings.Contains(path, "control-journal.json") }

// stoppedServiceCore is a service whose owner turned routing off after two
// crashes: memory and journal both say off, with a pending retry backoff.
func stoppedServiceCore(t *testing.T) (*Core, *fakeEngine, *fakeClock, *memoryFiles) {
	t.Helper()
	c, e, clock, files := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	if err := c.Routing(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.failureTimes = []int64{c.now() - 20000, c.now() - 10000}
	c.retryAttempts = 2
	c.retryAt = c.now() + 5000
	c.mu.Unlock()
	c.applyMu.Lock()
	err := c.persistJournal()
	c.applyMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if c.WantsRouting() || c.op.Journal.Values()["wanted"] != false || len(array(c.op.Journal.Values()["failures"])) != 2 {
		t.Fatal("starting state is not a committed stop with two recorded crashes")
	}
	e.calls = nil
	return c, e, clock, files
}

var turnOnRequests = []struct {
	name    string
	request func(*Core) error
}{
	{"sign-in", func(c *Core) error { return c.SignIn(context.Background()) }},
	{"routing on", func(c *Core) error { return c.Routing(context.Background(), true) }},
}

// A turn-on the journal refused must not survive in memory: once storage
// recovers, the supervisor would start routing the owner was told failed.
func TestRefusedTurnOnLeavesRoutingOffAfterStorageRecovers(t *testing.T) {
	for _, tc := range turnOnRequests {
		t.Run(tc.name, func(t *testing.T) {
			c, e, clock, files := stoppedServiceCore(t)
			before := c.retryStateNow()
			files.fail = true
			err := tc.request(c)
			if err == nil || !strings.Contains(err.Error(), "not committed") {
				t.Fatal("refused journal write was not reported", err)
			}
			if c.WantsRouting() || !c.retryStateNow().equal(before) {
				t.Fatal("refused intent changed memory", c.WantsRouting(), c.retryStateNow(), before)
			}
			files.fail = false
			clock.advance(60000) // past the old backoff
			for range 3 {
				if err := c.Supervise(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if slices.Contains(e.calls, "start") || e.Snapshot().Status != "off" {
				t.Fatal("supervisor started routing the owner was told was refused", e.calls)
			}
			if c.WantsRouting() || !c.retryStateNow().equal(before) || c.op.Journal.Values()["wanted"] != false {
				t.Fatal("intent or retry state changed after storage recovered")
			}
		})
	}
}

// The accepted path commits first and only then shows the supervisor the
// new intent, with a fresh retry budget.
func TestAcceptedTurnOnCommitsBeforeTheSupervisorSeesIt(t *testing.T) {
	for _, tc := range turnOnRequests {
		t.Run(tc.name, func(t *testing.T) {
			c, e, _, files := stoppedServiceCore(t)
			before := c.retryStateNow()
			journalWrites, early := 0, false
			files.beforeWrite = func(path string) {
				if !journalFile(path) {
					return
				}
				journalWrites++
				if journalWrites == 1 && (c.WantsRouting() || !c.retryStateNow().equal(before)) {
					early = true
				}
			}
			if err := tc.request(c); err != nil {
				t.Fatal(err)
			}
			files.beforeWrite = nil
			if journalWrites == 0 || early {
				t.Fatal("intent was published before its journal write", journalWrites, early)
			}
			if c.op.Journal.Values()["wanted"] != true || len(array(c.op.Journal.Values()["failures"])) != 0 {
				t.Fatal("journal does not hold the fresh intent", c.op.Journal.Values())
			}
			if after := c.retryStateNow(); !c.WantsRouting() || after.attempts != 0 || after.at != 0 || len(after.failures) != 0 {
				t.Fatal("accepted turn-on did not reset the retry budget", after)
			}
			if err := c.Supervise(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(e.calls, "start") || e.Snapshot().Status != "on" {
				t.Fatal("accepted intent did not start routing", e.calls)
			}
		})
	}
}

// Turning routing off and quitting follow the same rule: a refused write
// leaves routing on in memory and in the engine.
func TestRefusedStopKeepsRoutingOn(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request func(*Core) error
	}{
		{"routing off", func(c *Core) error { return c.Routing(context.Background(), false) }},
		{"quit", func(c *Core) error { return c.Shutdown(context.Background()) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, e, _, files := testCore(t, map[string]any{"lines": testLines()})
			c.op.ServiceMode = true
			if err := c.Routing(context.Background(), true); err != nil {
				t.Fatal(err)
			}
			if e.Snapshot().Status != "on" || c.op.Journal.Values()["wanted"] != true {
				t.Fatal("routing did not start")
			}
			e.calls = nil
			files.fail = true
			if err := tc.request(c); err == nil || !strings.Contains(err.Error(), "not committed") {
				t.Fatal("refused journal write was not reported", err)
			}
			c.mu.Lock()
			quitting := c.quitting
			c.mu.Unlock()
			if !c.WantsRouting() || quitting || slices.Contains(e.calls, "stop") || e.Snapshot().Status != "on" {
				t.Fatal("refused stop changed memory or the engine", c.WantsRouting(), quitting, e.calls)
			}
			files.fail = false
			if err := c.Supervise(context.Background()); err != nil {
				t.Fatal(err)
			}
			if slices.Contains(e.calls, "stop") || e.Snapshot().Status != "on" || c.op.Journal.Values()["wanted"] != true {
				t.Fatal("routing changed after storage recovered", e.calls)
			}
			if err := tc.request(c); err != nil {
				t.Fatal(err)
			}
			if c.WantsRouting() || c.op.Journal.Values()["wanted"] != false || e.Snapshot().Status != "off" {
				t.Fatal("accepted stop was not committed and applied", e.calls)
			}
		})
	}
}
