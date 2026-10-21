package control

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/control/engine"
)

// The Windows acceptance driver once took one engine reading, awaited a probe,
// and then judged a line added meanwhile against that old reading. Control
// must not have that shape: a line add during an in-flight probe goes through
// the real lines/add and app-line actions, and the late answer must neither
// count for the restarted line nor mark any line down.
func TestLineAddDuringProbeCannotApplyTheOldAnswer(t *testing.T) {
	c, e, clock, files := testCore(t, map[string]any{"lines": testLines()})
	var hold, stale atomic.Bool
	entered, release := make(chan struct{}), make(chan struct{})
	releaseProbe := sync.OnceFunc(func() { close(release) })
	var failedChecks atomic.Int32
	e.probe = func(r engine.ProbeRequest) engine.ProbeResult {
		if r.Line == "a1" && hold.CompareAndSwap(true, false) {
			close(entered)
			<-release
			failedChecks.Add(1)
			return engine.ProbeResult{Outcome: engine.LineFailed}
		}
		if stale.Load() {
			failedChecks.Add(1)
			return engine.ProbeResult{Outcome: engine.LineFailed}
		}
		return engine.ProbeResult{Outcome: engine.OK, Delay: ptr(float64(18))}
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Two healthy rounds after the start's own, so the lines carry history.
	for range 2 {
		clock.advance(15000)
		if err := c.Poll(context.Background()); err != nil {
			t.Fatal(err)
		}
	}

	jobDone := make(chan struct{})
	var detached atomic.Bool
	t.Cleanup(func() {
		releaseProbe()
		if detached.Load() {
			select {
			case <-jobDone:
			case <-time.After(5 * time.Second):
				t.Error("the held probe did not finish during cleanup")
			}
		}
	})
	c.op.ProbeBackground = func(line string, run func()) {
		if line == "a1" && detached.CompareAndSwap(false, true) {
			go func() { defer close(jobDone); run() }()
			return
		}
		run()
	}
	hold.Store(true)
	clock.advance(15000)
	if err := c.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the main line's probe never started")
	}

	c.mu.Lock()
	main := c.lanes["a1"]
	generation := main.generation
	accumulated := main.health.ProbePasses >= 2 && main.probing &&
		main.health.Up != nil && *main.health.Up && c.lanes["b2"].health.Up != nil && *c.lanes["b2"].health.Up
	c.adapters = append(c.adapters, map[string]any{"alias": "Cellular", "connected": true, "ipv4s": []any{"192.0.2.3"}})
	c.routes = append(c.routes, map[string]any{"interfaceAddress": "192.0.2.3"})
	c.mu.Unlock()
	if !accumulated {
		t.Fatal("the probe was not held over two healthy, accumulated lines")
	}

	actions := []struct {
		path string
		body map[string]any
	}{
		{"/api/lines/add", map[string]any{"alias": "Cellular"}},
		{"/api/app-line", map[string]any{"path": `C:\Apps\Main.exe`, "line": "a1"}},
		{"/api/app-line", map[string]any{"path": `C:\Apps\Second.exe`, "line": "b2"}},
	}
	for _, a := range actions {
		if _, err := c.Action(context.Background(), "POST", a.path, a.body); err != nil {
			t.Fatalf("%s: %v", a.path, err)
		}
	}

	c.mu.Lock()
	added := ""
	for _, l := range c.itemsLocked() {
		if l.Alias == "Cellular" {
			added = l.ID
		}
	}
	samePointer := c.lanes["a1"] == main
	bumped := main.generation != generation
	c.mu.Unlock()
	e.mu.Lock()
	started := len(e.s.StartedWith.Lines)
	pinned := map[string]string{}
	for _, p := range e.s.Policy.AppLines {
		pinned[p.Path] = p.LineID
	}
	e.mu.Unlock()
	// Credit the generation fence, not a replaced lane: the lane is the same
	// object, and only the restart for the added line moved its generation.
	if added == "" || started != 3 || !samePointer || !bumped {
		t.Fatalf("line add did not restart over the same lane: added=%q started=%d same=%v bumped=%v", added, started, samePointer, bumped)
	}
	if pinned[`C:\Apps\Main.exe`] != "a1" || pinned[`C:\Apps\Second.exe`] != "b2" {
		t.Fatalf("pins did not commit while the probe was held: %v", pinned)
	}
	select {
	case <-jobDone:
		t.Fatal("the probe finished before the actions committed")
	default:
	}

	// The held quick check and both of its full checks answer "failed".
	stale.Store(true)
	releaseProbe()
	select {
	case <-jobDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the held probe never finished")
	}
	stale.Store(false)
	if got := failedChecks.Load(); got != 3 {
		t.Fatalf("expected the held quick check and two failed full checks, got %d", got)
	}

	check := func(when string) {
		t.Helper()
		c.mu.Lock()
		defer c.mu.Unlock()
		if main.health.ProbeFails != 0 || main.health.Offline {
			t.Fatalf("%s: the answer from before the line add counted: fails=%d offline=%v", when, main.health.ProbeFails, main.health.Offline)
		}
		for _, id := range []string{"a1", "b2", added} {
			l := c.lanes[id]
			if l == nil || l.health.Up == nil || !*l.health.Up {
				t.Fatalf("%s: line %s is not up", when, id)
			}
		}
	}
	check("after the late answer")
	clock.advance(1000)
	if err := c.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	check("after the next poll")

	e.mu.Lock()
	policy := e.s.Policy
	e.mu.Unlock()
	for _, id := range []string{"a1", "b2", added} {
		if policy.Lanes[id] != id {
			t.Fatalf("line %s's apps moved to %q: %v", id, policy.Lanes[id], policy.Lanes)
		}
	}
	if len(policy.Blocked) != 0 {
		t.Fatalf("blocked lines: %v", policy.Blocked)
	}
	pinned = map[string]string{}
	for _, p := range policy.AppLines {
		pinned[p.Path] = p.LineID
	}
	if pinned[`C:\Apps\Main.exe`] != "a1" || pinned[`C:\Apps\Second.exe`] != "b2" {
		t.Fatalf("pins were not applied: %v", policy.AppLines)
	}
	files.mu.Lock()
	defer files.mu.Unlock()
	for _, line := range files.logs {
		if strings.Contains(line, " is down") || strings.Contains(line, "didn't reach the internet") {
			t.Fatalf("a line was judged from the old answer: %q", line)
		}
	}
	for _, event := range files.events {
		if m, ok := event.(map[string]any); ok && m["kind"] == "down" {
			t.Fatalf("down event: %v", m)
		}
	}
}
