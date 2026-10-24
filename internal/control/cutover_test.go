package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/usage"
)

// Spec §5.1: a clean adapter loss restarts without using the crash budget;
// more than three in ten minutes count like any other failure.
func TestAdapterLossRestartsFreeThenCounts(t *testing.T) {
	c, _, clock, _ := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	c.wanted = true
	for i := 1; i <= adapterLossesFree; i++ {
		clock.advance(1000)
		c.statusLocked(engine.Snapshot{Status: "error", Reason: engine.ReasonAdapterLost, FailureID: string(rune('a' + i))})
		c.statusLocked(engine.Snapshot{Status: "starting"})
		if len(c.failureTimes) != 0 {
			t.Fatalf("loss %d used the crash budget: %v", i, c.failureTimes)
		}
		if c.retryAt != c.now() {
			t.Fatalf("loss %d was not scheduled for an immediate restart: retryAt=%d now=%d", i, c.retryAt, c.now())
		}
	}
	clock.advance(1000)
	c.statusLocked(engine.Snapshot{Status: "error", Reason: engine.ReasonAdapterLost, FailureID: "fourth"})
	if len(c.failureTimes) != 1 || c.retryAt != c.now()+1000 {
		t.Fatalf("fourth loss in ten minutes must count and back off: failures=%v retryAt=%d now=%d", c.failureTimes, c.retryAt, c.now())
	}
	// Ten minutes later the window has emptied: losses are free again, and the
	// one counted failure stays in its own ten-minute budget untouched.
	clock.advance(10*60000 + 1)
	c.statusLocked(engine.Snapshot{Status: "starting"})
	c.statusLocked(engine.Snapshot{Status: "error", Reason: engine.ReasonAdapterLost, FailureID: "later"})
	if len(c.failureTimes) != 1 || c.retryAt != c.now() || len(c.adapterLosses) != 1 {
		t.Fatal("old losses still counted after ten minutes", c.failureTimes, c.adapterLosses, c.retryAt, c.now())
	}
	// The window is durable and a fresh routing intent clears it.
	if err := c.persistJournal(); err != nil {
		t.Fatal(err)
	}
	var saved struct {
		Losses []int64 `json:"adapterLosses"`
	}
	if err := json.Unmarshal(c.op.Journal.RawValues()["adapterLosses"], &saved.Losses); err != nil || len(saved.Losses) != 1 {
		t.Fatal("adapter losses not journaled", err, saved.Losses)
	}
	if err := c.commitIntent(routingIntent{wanted: true, fresh: true}); err != nil {
		t.Fatal(err)
	}
	if len(c.adapterLosses) != 0 {
		t.Fatal("fresh intent kept the loss window")
	}
}

func TestOrdinaryFailureStillCountsWithoutReason(t *testing.T) {
	c, _, _, _ := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	c.wanted = true
	c.statusLocked(engine.Snapshot{Status: "error", FailureID: "plain"})
	if len(c.failureTimes) != 1 || len(c.adapterLosses) != 0 {
		t.Fatal("an unclassified exit must count", c.failureTimes, c.adapterLosses)
	}
}

// Spec §4.5 and the follow-up contract: a quick result never stands in for a
// full check, and a result from a superseded engine instance is dropped.
func TestProbeResultsRequireKindAndInstance(t *testing.T) {
	ok := engine.ProbeResult{Outcome: engine.OK, Kind: "full", Instance: "i1"}
	if r := acceptProbe(ok, false, "i1", "i1"); r.Outcome != engine.OK {
		t.Fatal("matching full result rejected", r)
	}
	if r := acceptProbe(engine.ProbeResult{Outcome: engine.OK, Kind: "quick", Instance: "i1"}, false, "i1", "i1"); r.Outcome != engine.Unavailable {
		t.Fatal("quick result accepted for a full check", r)
	}
	if r := acceptProbe(engine.ProbeResult{Outcome: engine.LineFailed, Kind: "full", Instance: "i1"}, true, "i1", "i1"); r.Outcome != engine.Unavailable {
		t.Fatal("full result accepted for a quick check", r)
	}
	if r := acceptProbe(engine.ProbeResult{Outcome: engine.OK, Kind: "full", Instance: "old"}, false, "old", "new"); r.Outcome != engine.Unavailable {
		t.Fatal("result from a superseded instance accepted", r)
	}
	if r := acceptProbe(engine.ProbeResult{Outcome: engine.OK, Kind: "full", Instance: ""}, false, "i1", "i1"); r.Outcome != engine.Unavailable {
		t.Fatal("result with no instance accepted", r)
	}
}

func TestQuickPassNeverRestoresADownLine(t *testing.T) {
	c, e, clock, _ := testCore(t, map[string]any{"lines": testLines()})
	var probes atomic.Int64 // the two full checks of a round run concurrently
	e.probe = func(r engine.ProbeRequest) engine.ProbeResult {
		probes.Add(1)
		// A mis-kinded engine answers every check as a quick pass.
		return engine.ProbeResult{Outcome: engine.OK, Kind: "quick", Instance: "test-engine"}
	}
	ctx := context.Background()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.lanes["a1"].health.Offline = true // marked down: only a full HTTPS pass may restore it
	c.mu.Unlock()
	for i := 0; i < 6; i++ {
		clock.advance(5000)
		c.scheduleProbes(ctx, nil)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if probes.Load() == 0 {
		t.Fatal("no probe ran")
	}
	if !c.lanes["a1"].health.Offline {
		t.Fatal("quick passes restored a line that requires a full HTTPS check")
	}
}

// Spec §3.3: native closure cutoffs are apply points, recorded from the
// acknowledgement and sent with the line closure.
func TestClosureCutoffUsesTheNativeApplyPoint(t *testing.T) {
	c, e, _, _ := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	e.ackPoint = 41
	ctx := context.Background()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	s := e.Snapshot()
	if s.AppliedPoint == 0 {
		t.Fatal("precondition: fake engine reports no apply point")
	}
	intent := closureIntent{ID: "cap", Request: engine.CloseRequest{OperationID: "cap", Line: "b2", Instance: s.Instance}}
	p := c.policyLocked()
	p.Lanes["b2"], p.Blocked = "a1", []string{"b2"}
	if err := c.applyWithClosures(ctx, p, []closureIntent{intent}, c.generation); err != nil {
		t.Fatal(err)
	}
	pending, _ := c.pendingClosures()
	if len(pending) != 1 || pending[0].Request.StartedBeforePoint == 0 || !pending[0].Request.StartedBefore.IsZero() {
		t.Fatalf("cutoff not recorded as a point: %+v", pending)
	}
	c.deferClosures = map[string]uint64{}
	e.beforeClose = func(r engine.CloseRequest) error {
		if r.StartedBeforePoint != pending[0].Request.StartedBeforePoint || r.Line != "b2" {
			t.Fatalf("closure sent without its point: %+v", r)
		}
		return nil
	}
	if err := c.finishClosures(ctx, c.generation); err != nil {
		t.Fatal(err)
	}
	if left, _ := c.pendingClosures(); len(left) != 0 {
		t.Fatal("closure with a known point was not finished", left)
	}
}

// accountingEngine is the Core test fake with a real flow table behind the
// paged accounting, so byte totals are exact and independently generated.
type accountingEngine struct {
	*fakeEngine
	table   *flows.Table
	ackFail bool
	acks    int
}

func (a *accountingEngine) Totals(ctx context.Context, cursor string) (engine.TotalsPage, error) {
	page, err := a.table.PageTotals(cursor)
	if err != nil {
		return engine.TotalsPage{}, err
	}
	out := engine.TotalsPage{Instance: a.Snapshot().Instance, Apps: map[string]engine.Counter{}, Lines: map[string]engine.Counter{}, Cursor: page.Cursor, Receipt: page.Receipt, Count: page.Count}
	for id, v := range page.Apps {
		out.Apps[id] = engine.Counter{Up: v.Up, Down: v.Down, Generation: v.Generation}
	}
	for id, v := range page.Lines {
		out.Lines[id] = engine.Counter{Up: v.Up, Down: v.Down, Generation: v.Generation}
	}
	return out, nil
}
func (a *accountingEngine) AckTotals(ctx context.Context, opID, receipt string) error {
	if a.ackFail {
		return errors.New("control crashed before the acknowledgement left")
	}
	a.acks++
	_, err := a.table.AckTotals(receipt)
	return err
}

func accountingTable(t *testing.T) *flows.Table {
	t.Helper()
	table := flows.New(flows.Defaults(), nil)
	config := policy.Config{Lines: []platform.Line{{ID: "a1"}, {ID: "b2"}}}
	if _, err := table.Apply(policy.Revision{N: 1, Config: config, Hash: policy.Hash(config)}); err != nil {
		t.Fatal(err)
	}
	return table
}

func transfer(t *testing.T, table *flows.Table, app string, up, down uint64) {
	t.Helper()
	tuple := platform.Tuple{Source: netip.MustParseAddrPort("198.18.0.2:40001"), Destination: netip.MustParseAddrPort("203.0.113.9:443")}
	ticket, err := table.Begin("tcp", tuple)
	if err != nil {
		t.Fatal(err)
	}
	// The engine keys accounting by the owner's app id, which on Windows is
	// apppath.Key(path): the same key Control uses for pins and rows.
	if _, err := ticket.Resolve(platform.Owner{AppID: apps.AppKey(app), Path: app}); err != nil {
		t.Fatal(err)
	}
	ticket.Add(up, down)
	ticket.Close()
}

func routedUsage(t *testing.T, files *memoryFiles) *usage.Routed {
	t.Helper()
	b, err := files.ReadFile(filepath.Join("/test", "usage.json"))
	if err != nil {
		t.Fatal("usage record missing", err)
	}
	routed := usage.LoadRouted(b)
	if routed == nil {
		t.Fatal("usage record has no routed section", string(b))
	}
	return routed
}

// Spec §5.10: the durable store is committed before the acknowledgement, so
// a crash on either side of the ack neither loses nor double counts bytes.
func TestTotalsConsumerSurvivesCrashesAroundTheAck(t *testing.T) {
	c, e, clock, files := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	table := accountingTable(t)
	acct := &accountingEngine{fakeEngine: e, table: table}
	c.op.Engine = acct
	ctx := context.Background()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	transfer(t, table, "C:/apps/one.exe", 1000, 2000)
	if err := c.readTotals(ctx, acct, c.generation); err != nil {
		t.Fatal(err)
	}
	first := routedUsage(t, files)
	if got := first.Apps[apps.AppKey("C:/apps/one.exe")]; got == nil || got.Up != 1000 || got.Down != 2000 || acct.acks != 1 {
		t.Fatalf("first read not committed exactly: %+v acks=%d", got, acct.acks)
	}
	// Crash between the durable write and the ack: the next Control re-reads
	// the same (unretired) counters and must not add them again.
	transfer(t, table, "C:/apps/one.exe", 10, 20)
	acct.ackFail = true
	if err := c.readTotals(ctx, acct, c.generation); err == nil {
		t.Fatal("lost acknowledgement was reported as success")
	}
	acct.ackFail = false
	restarted, _, _, _ := testCoreWithFiles(t, files, clock)
	restarted.op.ServiceMode = true
	restarted.op.Engine = acct
	if err := restarted.readTotals(ctx, acct, restarted.generation); err != nil {
		t.Fatal(err)
	}
	second := routedUsage(t, files)
	if got := second.Apps[apps.AppKey("C:/apps/one.exe")]; got.Up != 1010 || got.Down != 2020 {
		t.Fatalf("bytes double counted or lost across the commit/ack crash: %+v", got)
	}
	// Crash after the ack, before the next read: the acknowledged idle entry
	// is retired, and new traffic for the same app returns in a new generation.
	transfer(t, table, "C:/apps/one.exe", 5, 7)
	again, _, _, _ := testCoreWithFiles(t, files, clock)
	again.op.ServiceMode = true
	again.op.Engine = acct
	if err := again.readTotals(ctx, acct, again.generation); err != nil {
		t.Fatal(err)
	}
	third := routedUsage(t, files)
	if got := third.Apps[apps.AppKey("C:/apps/one.exe")]; got.Up != 1015 || got.Down != 2027 {
		t.Fatalf("bytes lost or double counted across the ack/read crash: %+v", got)
	}
	if lines := third.Lines["a1"]; lines == nil || lines.Up != 1015 || lines.Down != 2027 {
		t.Fatalf("line totals do not match: %+v", third.Lines)
	}
}

func TestTotalsAreNotAcknowledgedWhenTheCommitFails(t *testing.T) {
	c, e, clock, files := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	table := accountingTable(t)
	acct := &accountingEngine{fakeEngine: e, table: table}
	c.op.Engine = acct
	ctx := context.Background()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	transfer(t, table, "C:/apps/two.exe", 3, 4)
	files.failPrefix = filepath.Join("/test", "usage.json")
	if err := c.readTotals(ctx, acct, c.generation); err == nil || acct.acks != 0 {
		t.Fatal("accounting acknowledged without a durable commit", err, acct.acks)
	}
	// An unchanged second read must not ack either: the bytes are still only
	// in memory. (On the first version of this consumer it did, and a later
	// crash lost them.)
	if err := c.readTotals(ctx, acct, c.generation); err == nil || acct.acks != 0 {
		t.Fatal("unchanged read acknowledged bytes that were never written", err, acct.acks)
	}
	// Once the disk is back, the unchanged read writes first, then acks.
	files.failPrefix = ""
	if err := c.readTotals(ctx, acct, c.generation); err != nil || acct.acks != 1 {
		t.Fatal("recovered commit did not acknowledge", err, acct.acks)
	}
	if got := routedUsage(t, files).Apps[apps.AppKey("C:/apps/two.exe")]; got == nil || got.Up != 3 || got.Down != 4 {
		t.Fatalf("durable record after recovery: %+v", got)
	}
	// A restart after the ack still has every byte exactly once.
	transfer(t, table, "C:/apps/two.exe", 1, 1)
	restarted, _, _, _ := testCoreWithFiles(t, files, clock)
	restarted.op.ServiceMode = true
	restarted.op.Engine = acct
	if err := restarted.readTotals(ctx, acct, restarted.generation); err != nil {
		t.Fatal(err)
	}
	if got := routedUsage(t, files).Apps[apps.AppKey("C:/apps/two.exe")]; got.Up != 4 || got.Down != 5 {
		t.Fatalf("bytes lost or double counted across the failed commit and restart: %+v", got)
	}
}

// Two usage writers (the minute timer and the accounting consumer) must not
// let an older snapshot replace a newer, already acknowledged one. The writer
// holds one lock across snapshot and write; without it the second writer
// below would write immediately.
func TestUsageWritersAreSerialized(t *testing.T) {
	c, _, _, files := testCore(t, map[string]any{"lines": testLines()})
	usagePath := filepath.Join("/test", "usage.json")
	c.usage.Routed = usage.NewRouted()
	c.usage.Routed.Absorb("i1", map[string]usage.RoutedCounter{"app": {Up: 1, Generation: "1"}}, nil)
	var second sync.WaitGroup
	secondWrote := make(chan struct{}, 1)
	first := true
	files.beforeWrite = func(p string) {
		if !strings.HasPrefix(p, usagePath) || !first {
			return
		}
		first = false
		// While the first writer is between snapshot and write, a newer state
		// arrives and a second writer starts. It must wait.
		c.mu.Lock()
		c.usage.Routed.Absorb("i1", map[string]usage.RoutedCounter{"app": {Up: 2, Generation: "1"}}, nil)
		c.routedGeneration++
		c.mu.Unlock()
		second.Add(1)
		go func() {
			defer second.Done()
			if err := c.SaveUsage(); err != nil {
				t.Error(err)
			}
			secondWrote <- struct{}{}
		}()
		select {
		case <-secondWrote:
			t.Error("second usage writer wrote while the first held an older snapshot")
		case <-time.After(100 * time.Millisecond):
		}
	}
	if err := c.SaveUsage(); err != nil {
		t.Fatal(err)
	}
	second.Wait()
	files.beforeWrite = nil
	if got := routedUsage(t, files).Apps["app"]; got == nil || got.Up != 2 {
		t.Fatalf("the newer snapshot did not win: %+v", got)
	}
}

// While the crash budget cannot be written, the supervisor holds the restart
// back; the first durable write releases it.
func TestUnwritableBudgetBlocksTheRestart(t *testing.T) {
	c, e, _, files := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	c.wanted = true
	e.mu.Lock()
	e.s = engine.Snapshot{Status: "error", Instance: "lost", FailureID: "lost", Reason: engine.ReasonAdapterLost}
	e.mu.Unlock()
	files.failPrefix = c.op.Journal.File
	err := c.Supervise(context.Background())
	if err == nil || !strings.Contains(err.Error(), "crash budget") {
		t.Fatal("restart was not held back by the unwritable budget", err)
	}
	if slices.Contains(e.calls, "start") {
		t.Fatal("engine restarted while its loss was not durable", e.calls)
	}
	files.failPrefix = ""
	if err := c.Supervise(context.Background()); err != nil {
		t.Fatal(err)
	}
	var losses []int64
	if err := json.Unmarshal(c.op.Journal.RawValues()["adapterLosses"], &losses); err != nil || len(losses) != 1 || !slices.Contains(e.calls, "start") {
		t.Fatal("durable budget did not release the restart", err, losses, e.calls)
	}
}

// A failure or adapter loss seen by the supervisor is journaled before the
// restart it allows, so a crash during that start cannot forget it.
func TestStartupFailureIsPersistedBeforeTheRestart(t *testing.T) {
	c, e, _, _ := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	c.wanted = true
	e.mu.Lock()
	e.s = engine.Snapshot{Status: "error", Instance: "lost-while-down", FailureID: "lost-while-down", Reason: engine.ReasonAdapterLost}
	e.mu.Unlock()
	e.beforeStart = func() {
		var losses []int64
		if err := json.Unmarshal(c.op.Journal.RawValues()["adapterLosses"], &losses); err != nil || len(losses) != 1 {
			t.Fatal("restart began before the adapter loss was journaled", err, losses)
		}
	}
	if err := c.Supervise(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(e.calls, "start") {
		t.Fatal("free adapter loss did not restart at once", e.calls)
	}
}

func TestAdapterEngineWithoutAccountingKeepsUsageShape(t *testing.T) {
	c, e, _, files := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	if _, ok := any(e).(engine.Accounting); ok {
		t.Fatal("the plain fake must not offer accounting")
	}
	c.scheduleTotals(context.Background(), c.generation)
	if err := c.SaveUsage(); err != nil {
		t.Fatal(err)
	}
	b, _ := files.ReadFile(filepath.Join("/test", "usage.json"))
	var saved map[string]any
	if json.Unmarshal(b, &saved) != nil || saved["routed"] != nil {
		t.Fatal("adapter-era usage record grew a routed section", string(b))
	}
}
