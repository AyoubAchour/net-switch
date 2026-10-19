package control

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/control/engine"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
)

func TestRepeatedRouteSnapshotDoesNotCountTwice(t *testing.T) {
	c, e, clock, _ := testCore(t, map[string]any{"lines": testLines()})
	c.sampleLinesLocked(e.Snapshot())
	c.routes = []map[string]any{{"interfaceAddress": "192.0.2.2"}}
	clock.advance(5000)
	c.routesAt = c.now()
	c.sampleLinesLocked(e.Snapshot())
	for i := 0; i < 10; i++ {
		clock.advance(1000)
		c.sampleLinesLocked(e.Snapshot())
	}
	if h := c.lanes["a1"].health; h.RouteMisses != 1 || h.Up == nil || !*h.Up {
		t.Fatalf("repeated snapshot changed health: %+v", h)
	}
	c.routesAt = c.now()
	c.sampleLinesLocked(e.Snapshot())
	clock.advance(1000)
	c.sampleLinesLocked(e.Snapshot())
	if h := c.lanes["a1"].health; *h.Up || h.Reason == nil || *h.Reason != "no default route" {
		t.Fatal(h)
	}
}

func TestNetworkSnapshotsOnlyMoveForward(t *testing.T) {
	c, _, clock, _ := testCore(t, map[string]any{"lines": testLines()})
	snapshot := func(at int64, metric float64) map[string]any {
		return map[string]any{"readAt": float64(at), "adapters": []any{map[string]any{"alias": "Ethernet", "status": "Up", "gateway": "192.0.2.254", "metric": metric}}, "defaultRoutes": []any{map[string]any{"interfaceAddress": "192.0.2.1"}}}
	}
	at := clock.Now().UnixMilli()
	for _, input := range []map[string]any{snapshot(at, 10), snapshot(at-1, 99), snapshot(at, 98)} {
		if err := c.ApplyNetwork(context.Background(), input, c.generation); err != nil {
			t.Fatal(err)
		}
	}
	if c.adapters[0]["metric"] != float64(10) || c.routesAt != at {
		t.Fatal("stale snapshot replaced newer data")
	}
	if err := c.ApplyNetwork(context.Background(), snapshot(at+1, 11), c.generation); err != nil {
		t.Fatal(err)
	}
	if c.adapters[0]["metric"] != float64(11) {
		t.Fatal("new snapshot not applied")
	}
}

func TestTestingEligibilityAndMissingRouteProbeFrequency(t *testing.T) {
	c, e, clock, _ := testCore(t, map[string]any{"lines": testLines()})
	c.sampleLinesLocked(e.Snapshot())
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.exhausted["b2"] = true
	if c.canTestLocked("b2", e.Snapshot()) || c.canTestLocked("not-started", e.Snapshot()) {
		t.Fatal("tested an exhausted or unbound line")
	}
	lane := c.lanes["a1"]
	lane.health.Up, lane.health.Reason = ptr(false), ptr("no default route")
	lane.probeAt = ptr(c.now())
	quick, full := 0, 0
	e.probe = func(r engine.ProbeRequest) engine.ProbeResult {
		if r.Quick {
			quick++
		} else {
			full++
		}
		return engine.ProbeResult{Outcome: engine.OK, Delay: ptr(21.0)}
	}
	for i := 0; i < 3; i++ {
		clock.advance(5000)
		c.scheduleProbes(context.Background(), nil)
	}
	if quick != 1 || full != 0 {
		t.Fatalf("missing route triggered aggressive checks: quick=%d full=%d", quick, full)
	}
}

func TestRealTrafficKeepsLastMeasuredPing(t *testing.T) {
	c, e, clock, _ := testCore(t, map[string]any{"lines": testLines()})
	c.sampleLinesLocked(e.Snapshot())
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.lanes["a1"].delay = ptr(37.0)
	c.lanes["a1"].probeAt = nil
	flows := []engine.Connection{}
	for _, host := range []string{"one.example", "two.example"} {
		flows = append(flows, engine.Connection{Connection: apps.Connection{Chains: []string{"line-a1"}, Download: 1, Start: clock.Now().Format(time.RFC3339Nano)}, Host: host})
	}
	e.probe = func(r engine.ProbeRequest) engine.ProbeResult {
		if r.Line == "a1" {
			t.Error("busy line sent a probe")
		}
		return engine.ProbeResult{Outcome: engine.Unavailable}
	}
	c.scheduleProbes(context.Background(), flows)
	if delay := c.lanes["a1"].delay; delay == nil || *delay != 37 {
		t.Fatal("real traffic cleared the ping")
	}
}

func TestReconnectOnlyExcludesUnknownAndWindowsServices(t *testing.T) {
	c, _, _, _ := testCore(t, nil)
	for _, exe := range []string{"node", "python", "pythonw", "java", "javaw", "cmd", "powershell", "pwsh", "wscript", "cscript", "dotnet"} {
		if c.describeLocked(`C:\Apps\` + exe + ".exe")["reconnectable"] != true {
			t.Fatal(exe)
		}
	}
	for _, path := range []string{"", `C:\Windows\System32\svchost.exe`} {
		if c.describeLocked(path)["reconnectable"] != false {
			t.Fatal(path)
		}
	}
}

func TestJournalFailureCannotBlockLaneSwitch(t *testing.T) {
	c, e, _, files := testCore(t, map[string]any{"lines": testLines()})
	c.sampleLinesLocked(e.Snapshot())
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	files.fail = true
	c.lanes["a1"].health.Up = ptr(false)
	if err := c.ApplyPolicy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.Snapshot().Policy.Lanes["a1"] != "b2" {
		t.Fatal("journal failure blocked failover")
	}
	if !strings.Contains(strings.Join(files.logs, "\n"), "CONTROL JOURNAL WRITE FAILED") {
		t.Fatal("missing journal diagnostic")
	}
}

func TestClosureFailuresBackOffWithoutBlockingOthersOrRewritingRevision(t *testing.T) {
	c, e, clock, files := testCore(t, map[string]any{"lines": testLines()})
	c.sampleLinesLocked(e.Snapshot())
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.applyMu.Lock()
	for _, id := range []string{"failed", "healthy"} {
		_ = c.saveIntent(closureIntent{ID: id, Purpose: "reconnect", Label: "Firefox", Revision: e.Snapshot().AppliedRevision,
			Request: engine.CloseRequest{OperationID: id, Instance: e.Snapshot().Instance, StartedBefore: clock.Now(), ConnectionIDs: []string{id}}})
	}
	c.applyMu.Unlock()
	attempts := 0
	e.beforeClose = func(r engine.CloseRequest) error {
		if r.OperationID == "failed" {
			attempts++
			return errors.New("lost answer")
		}
		return nil
	}
	if err := c.ReplayClosures(context.Background()); err == nil || !strings.Contains(err.Error(), "Reconnect Firefox") {
		t.Fatal(err)
	}
	pending, _ := c.pendingClosures()
	if len(pending) != 1 || pending[0].ID != "failed" || !reflect.DeepEqual(e.calls[len(e.calls)-1:], []string{"close:healthy"}) {
		t.Fatal("first failure blocked another intent")
	}
	writes, revision := len(files.writes), c.revision
	for i := 0; i < 19; i++ {
		clock.advance(100)
		_ = c.closeExhausted(context.Background(), nil, c.generation)
		_ = c.ReplayClosures(context.Background())
	}
	if attempts != 1 || c.revision != revision || len(files.writes) != writes {
		t.Fatalf("waiting retry wrote or ran again: attempts=%d revision=%d writes=%d", attempts, c.revision, len(files.writes))
	}
	clock.advance(100)
	_ = c.ReplayClosures(context.Background())
	if attempts != 2 {
		t.Fatal("retry did not resume")
	}
}

type contextEngine struct {
	engine.Engine
	seen []context.Context
}

func (e *contextEngine) Start(ctx context.Context, p engine.Policy) error {
	e.seen = append(e.seen, ctx)
	return e.Engine.Start(ctx, p)
}
func (e *contextEngine) Stop(ctx context.Context) error {
	e.seen = append(e.seen, ctx)
	return e.Engine.Stop(ctx)
}

func TestDroppedLifecycleRequestsUseServiceContext(t *testing.T) {
	c, e, _, _ := testCore(t, map[string]any{"lines": testLines()})
	checked := &contextEngine{Engine: e}
	c.op.Engine = checked
	quit := false
	h := &HTTP{Core: c, Port: 47821, Token: "test", Quit: func() { quit = true }}
	for _, step := range []struct{ route, body string }{{"routing", `{"on":true}`}, {"routing", `{"on":false}`}, {"routing", `{"on":true}`}, {"quit", `{}`}} {
		ctx, cancel := context.WithCancel(context.Background())
		request := httptest.NewRequest("POST", "http://127.0.0.1:47821/api/"+step.route, bytes.NewBufferString(step.body)).WithContext(ctx)
		request.Header.Set("X-Token", "test")
		cancel()
		recorder := httptest.NewRecorder()
		h.ServeHTTP(recorder, request)
		if recorder.Code != 200 {
			t.Fatalf("%s: %d %s", step.route, recorder.Code, recorder.Body.String())
		}
	}
	if !quit || e.Snapshot().Status != "off" || len(checked.seen) != 4 {
		t.Fatal("dropped lifecycle work")
	}
	for _, ctx := range checked.seen {
		if ctx != c.ctx {
			t.Fatal("request context reached engine")
		}
	}
}

func TestWindowReportsTargetsActuallyUsed(t *testing.T) {
	c, _, _, _ := testCore(t, nil)
	want := []string{"1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"}
	if got := js.Object(c.State()["settings"])["probeTargets"]; !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
	c.values["probeTargets"], c.values["probeTargetsCustom"] = []any{"8.8.4.4:443"}, true
	if got := js.Object(c.State()["settings"])["probeTargets"]; fmt.Sprint(got) != "[8.8.4.4:443]" {
		t.Fatal(got)
	}
}
