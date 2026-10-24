package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/control/engine"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
	"github.com/AyoubAchour/net-switch/internal/lines"
	"github.com/AyoubAchour/net-switch/internal/platform"
	"github.com/AyoubAchour/net-switch/internal/settings"
	"github.com/AyoubAchour/net-switch/internal/usage"
)

type memoryFiles struct {
	mu            sync.Mutex
	data          map[string][]byte
	fail          bool
	failPrefix    string
	writes        []recordedWrite
	logs          []string
	removes       []string
	spawns        []map[string]any
	outsideCloses []any
	events        []any
	order         []string
	syncs         []string
	beforeWrite   func(path string)
}

func (f *memoryFiles) recordOrder(kind string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.order = append(f.order, kind)
}

func (f *memoryFiles) recordWriteOrder(path string) {
	if controlFile(path) || engineFile(path) {
		f.order = append(f.order, "write:"+filepath.Base(path))
	}
}

type recordedWrite struct {
	Path  string
	Bytes []byte
}

func (f *memoryFiles) ReadFile(p string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.data[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte{}, b...), nil
}
func (f *memoryFiles) WriteFile(p string, b []byte, _ fs.FileMode) error {
	if f.beforeWrite != nil {
		f.beforeWrite(p)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail || f.failPrefix != "" && strings.HasPrefix(p, f.failPrefix) {
		return errors.New("disk full")
	}
	f.data[p] = append([]byte{}, b...)
	if !strings.HasSuffix(p, ".tmp") {
		f.writes = append(f.writes, recordedWrite{Path: p, Bytes: append([]byte{}, b...)})
		f.recordWriteOrder(p)
	}
	return nil
}
func (f *memoryFiles) Rename(a, b string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.data[a]
	if !ok {
		return fs.ErrNotExist
	}
	f.data[b] = v
	f.writes = append(f.writes, recordedWrite{Path: b, Bytes: append([]byte{}, v...)})
	f.recordWriteOrder(b)
	delete(f.data, a)
	return nil
}
func (f *memoryFiles) Remove(p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.data, p)
	f.removes = append(f.removes, p)
	f.order = append(f.order, "remove:"+filepath.Base(p))
	return nil
}

type fakeClock struct {
	mu        sync.Mutex
	at        time.Time
	beforeNow func()
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.beforeNow != nil {
		f.beforeNow()
	}
	return f.at
}
func (f *fakeClock) After(time.Duration) <-chan time.Time { return make(chan time.Time) }
func (f *fakeClock) advance(ms int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.at = f.at.Add(time.Duration(ms) * time.Millisecond)
}

type fakeEngine struct {
	mu              sync.Mutex
	s               engine.Snapshot
	connections     []engine.Connection
	calls           []string
	commands        []map[string]any
	failure         error
	beforeApply     func(engine.Revision)
	probe           func(engine.ProbeRequest) engine.ProbeResult
	real            engine.Engine
	wireConnections json.RawMessage
	requests        []map[string]any
	readConnections func(context.Context) ([]engine.Connection, error)
	replies         []recordedReply
	resourceIDs     map[string]string
	beforeStart     func()
	beforeClose     func(engine.CloseRequest) error
	killFailure     string
	directoryLists  [][]string
	// ackPoint, when set, makes the fake answer like the native engine: every
	// acknowledgement carries a growing apply point.
	ackPoint uint64
}
type recordedReply struct {
	Route  string
	Status int
	Body   any
}

func (f *fakeEngine) Snapshot() engine.Snapshot {
	if f.real != nil {
		return f.real.Snapshot()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.s
}
func (f *fakeEngine) Fail(err error) {
	if f.real != nil {
		f.real.Fail(err)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.s.Status = "error"
	text := err.Error()
	f.s.Error = &text
}
func (f *fakeEngine) ForgetLane(id string) {
	if e, ok := f.real.(interface{ ForgetLane(string) }); ok {
		e.ForgetLane(id)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.s.Policy.Lanes, id)
}
func (f *fakeEngine) Start(ctx context.Context, p engine.Policy) error {
	if f.beforeStart != nil {
		f.beforeStart()
	}
	if f.real != nil {
		return f.real.Start(ctx, p)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "start")
	f.s.Status = "on"
	f.s.Instance = "test-engine"
	f.s.Policy = p
	f.s.StartedWith = &p
	f.s.AppliedRevision = 0
	f.s.StartedAt = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	return f.failure
}
func (f *fakeEngine) Stop(ctx context.Context) error {
	if f.real != nil {
		return f.real.Stop(ctx)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "stop")
	if f.failure == nil {
		f.s.Status = "off"
	}
	return f.failure
}
func (f *fakeEngine) Apply(ctx context.Context, r engine.Revision) (engine.Acknowledgement, error) {
	if f.real != nil {
		return f.real.Apply(ctx, r)
	}
	if f.beforeApply != nil {
		f.beforeApply(r)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "apply")
	if f.failure != nil {
		return engine.Acknowledgement{}, f.failure
	}
	if f.s.Status == "on" && f.s.StartedWith != nil && len(f.s.StartedWith.Lines) > 1 {
		for _, line := range r.Policy.Lines {
			target := r.Policy.Lanes[line.ID]
			if target != "" && (f.s.AppliedRevision == 0 || f.s.Policy.Lanes[line.ID] != target) {
				f.commands = append(f.commands, map[string]any{"method": "PUT", "route": "/proxies/lane-" + line.ID, "body": map[string]any{"name": "line-" + target}})
			}
		}
	}
	f.s.Policy = r.Policy
	f.s.AppliedRevision = r.Number
	f.s.AppliedHash = r.Hash
	ack := engine.Acknowledgement{Number: r.Number, Hash: r.Hash, Instance: f.s.Instance, AppliedAt: f.s.StartedAt}
	if f.ackPoint != 0 {
		f.ackPoint++
		f.s.AppliedPoint, f.s.AppliedAt = f.ackPoint, time.Time{}
		ack.Point, ack.AppliedAt = f.ackPoint, time.Time{}
	}
	return ack, nil
}
func (f *fakeEngine) CloseFlows(ctx context.Context, r engine.CloseRequest) (engine.CloseResult, error) {
	if f.beforeClose != nil {
		if err := f.beforeClose(r); err != nil {
			return engine.CloseResult{}, err
		}
	}
	if f.real != nil {
		return f.real.CloseFlows(ctx, r)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range r.ConnectionIDs {
		f.calls = append(f.calls, "close:"+id)
		f.commands = append(f.commands, map[string]any{"method": "DELETE", "route": "/connections/" + id})
	}
	return engine.CloseResult{Closed: len(r.ConnectionIDs)}, nil
}
func (f *fakeEngine) Connections(ctx context.Context) ([]engine.Connection, error) {
	if f.readConnections != nil {
		return f.readConnections(ctx)
	}
	if f.real != nil {
		return f.real.Connections(ctx)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]engine.Connection{}, f.connections...), nil
}
func (f *fakeEngine) Probe(ctx context.Context, r engine.ProbeRequest) engine.ProbeResult {
	if f.real != nil {
		return f.real.Probe(ctx, r)
	}
	result := engine.ProbeResult{Outcome: engine.OK, Delay: ptr(float64(18))}
	if f.probe != nil {
		result = f.probe(r)
	}
	// Like the adapter dialect of the real client, stamp the kind asked for and
	// the current instance unless the test set them itself.
	if result.Kind == "" {
		result.Kind = "full"
		if r.Quick {
			result.Kind = "quick"
		}
	}
	if result.Instance == "" {
		result.Instance = f.Snapshot().Instance
	}
	return result
}

type fakePlatform struct {
	network     map[string]any
	calls       []string
	mu          sync.Mutex
	recordClose func(any)
	probe       func(map[string]any) (any, error)
	override    func(string, map[string]any) (any, error, bool)
}

func (f *fakePlatform) Call(_ context.Context, name string, a map[string]any) (any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
	if f.override != nil {
		if v, err, ok := f.override(name, a); ok {
			return v, err
		}
	}
	switch name {
	case "line-check":
		if f.probe != nil {
			return f.probe(a)
		}
		return nil, fmt.Errorf("no fake probe result")
	case "network":
		return f.network, nil
	case "elevated":
		return true, nil
	case "close-tcp":
		if f.recordClose != nil {
			f.recordClose(a["connections"])
		}
		n := 0
		if tt, ok := a["connections"].([]*apps.Tuple); ok {
			n = len(tt)
		}
		if tt, ok := a["connections"].([]platform.TCPSelector); ok {
			n = len(tt)
		}
		return map[string]any{"closed": float64(n), "failed": float64(0), "gone": float64(0), "codes": []any{}}, nil
	case "installed-apps":
		return []any{}, nil
	}
	return nil, nil
}
func (*fakePlatform) Stream(context.Context, string, func([]byte), func(error)) {}
func testCore(t *testing.T, initial map[string]any) (*Core, *fakeEngine, *fakeClock, *memoryFiles) {
	t.Helper()
	files := &memoryFiles{data: map[string][]byte{}}
	b, err := js.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	files.data[filepath.Join("/test", "settings.json")] = b
	clock := &fakeClock{at: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)}
	return testCoreWithFiles(t, files, clock)
}

// testCoreWithFiles builds a Core over existing files, like a service restart
// over the same data folder.
func testCoreWithFiles(t *testing.T, files *memoryFiles, clock *fakeClock) (*Core, *fakeEngine, *fakeClock, *memoryFiles) {
	t.Helper()
	var serial atomic.Uint64
	id := func() string { return fmt.Sprintf("%012x", serial.Add(1)) }
	io := settings.Options{Files: files, Now: clock.Now, ID: id, Sleep: func(time.Duration) {}}
	store := settings.New("/test", io)
	if _, err := store.Load(); err != nil {
		t.Fatal(err)
	}
	undo := io
	undo.FileName = "windows-undo.json"
	undo.Defaults = map[string]any{"metrics": map[string]any{}, "policy": map[string]any{}}
	us := settings.New("/test", undo)
	if _, err := us.Load(); err != nil {
		t.Fatal(err)
	}
	journal := io
	journal.SyncFile = func(path string) error {
		files.mu.Lock()
		defer files.mu.Unlock()
		files.syncs = append(files.syncs, path)
		return nil
	}
	journal.FileName = "control-journal.json"
	journal.Defaults = map[string]any{"revision": float64(0), "closures": []any{}, "desired": map[string]any{}, "settings": map[string]any{}}
	j := settings.New("/test", journal)
	if _, err := j.Load(); err != nil {
		t.Fatal(err)
	}
	f := &fakeEngine{s: engine.Snapshot{Status: "off", Instance: "test-engine", Policy: engine.Policy{}}}
	p := &fakePlatform{recordClose: func(v any) {
		b, _ := js.Marshal(v)
		decoded, _ := js.Decode(b)
		files.outsideCloses = append(files.outsideCloses, decoded)
		files.recordOrder("outside-close")
	}}
	c, err := New(context.Background(), Options{Engine: f, Platform: p, Settings: store, Undo: us, Journal: j, IO: io, Clock: clock, Location: time.UTC, Mode: "tun", Version: "0.3.1", UserDir: "/test", ID: id, LineID: func() string { return fmt.Sprintf("%06x", serial.Add(1)) }, Background: func(fn func()) { fn() }, Log: func(s string) {
		files.mu.Lock()
		files.logs = append(files.logs, s)
		files.order = append(files.order, traceLogKey(s))
		files.mu.Unlock()
	}, Event: func(v map[string]any) {
		b, _ := js.Marshal(v)
		out, _ := js.Decode(b)
		files.events = append(files.events, out)
		files.recordOrder("event")
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.cancel)
	c.elevated = true
	for i, line := range c.itemsLocked() {
		address := fmt.Sprintf("192.0.2.%d", i+1)
		c.adapters = append(c.adapters, map[string]any{"alias": line.Alias, "ipv4s": []any{address}})
		c.routes = append(c.routes, map[string]any{"interfaceAddress": address})
	}
	c.routesAt = c.now()
	c.routesSequence = c.networkIssued.Add(1)
	return c, f, clock, files
}
func testLines() []lines.Line {
	return []lines.Line{{ID: "a1", Alias: "Ethernet", Label: "Ethernet", Kind: ptr("wired"), Weight: 1}, {ID: "b2", Alias: "Wi-Fi", Label: "Wi-Fi", Kind: ptr("wifi"), Weight: 1}}
}

func TestCapsPersistBeforeApplyAndCloseOnlyAfterAck(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mainCap bool
		want    string
	}{{"moved secondary", false, "close:old-secondary"}, {"blocked secondary and main exception", true, "close:old-secondary"}} {
		t.Run(tc.name, func(t *testing.T) {
			items := testLines()
			items[1].Cap = &lines.Cap{Bytes: 100, Period: "day"}
			if tc.mainCap {
				items[0].Cap = &lines.Cap{Bytes: 100, Period: "day"}
			}
			c, e, clock, _ := testCore(t, map[string]any{"lines": items})
			c.values["lines"] = items
			for _, l := range c.lanes {
				l.health.Up = ptr(true)
				l.health.HadAddress = ptr(true)
			}
			if err := c.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			e.calls = nil
			c.closePending["b2"] = true
			c.exhausted["b2"] = true
			if tc.mainCap {
				c.closePending["a1"] = true
				c.exhausted["a1"] = true
			}
			connections := []engine.Connection{{Connection: apps.Connection{ID: "old-secondary", Chains: []string{"line-b2"}}}, {Connection: apps.Connection{ID: "old-main", Chains: []string{"line-a1"}}}}
			e.beforeApply = func(r engine.Revision) {
				v := c.op.Journal.Values()
				if uint64(js.Number(v["revision"])) != r.Number || len(array(v["closures"])) != 1 {
					t.Fatal("revision and closure were not persisted before apply")
				}
				for _, call := range e.calls {
					if strings.HasPrefix(call, "close:") {
						t.Fatal("closed before acknowledgement")
					}
				}
			}
			clock.advance(1000)
			if err := c.closeExhausted(context.Background(), connections, c.generation); err != nil {
				t.Fatal(err)
			}
			if err := c.finishClosures(context.Background(), c.generation); err != nil {
				t.Fatal(err)
			}
			wantCalls := []string{"apply", tc.want}
			if tc.mainCap {
				if !reflect.DeepEqual(e.calls, []string{"apply"}) || len(array(c.op.Journal.Values()["closures"])) != 1 {
					t.Fatal("new block did not retain its deferred closure")
				}
				clock.advance(1000)
				c.pollSequence++
				if err := c.closeExhausted(context.Background(), connections, c.generation); err != nil {
					t.Fatal(err)
				}
				if err := c.finishClosures(context.Background(), c.generation); err != nil {
					t.Fatal(err)
				}
				wantCalls = []string{"apply", tc.want}
			}
			if !reflect.DeepEqual(e.calls, wantCalls) {
				t.Fatal(e.calls)
			}
			if len(array(c.op.Journal.Values()["closures"])) != 0 {
				t.Fatal("acknowledged closure not completed")
			}
		})
	}
}
func TestFailedApplyNeverClosesAndLeavesIntent(t *testing.T) {
	c, e, _, _ := testCore(t, map[string]any{"lines": testLines()})
	c.exhausted["b2"] = true
	c.closePending["b2"] = true
	e.s.Status = "on"
	e.failure = errors.New("reload failed")
	err := c.closeExhausted(context.Background(), []engine.Connection{{Connection: apps.Connection{ID: "old", Chains: []string{"line-b2"}}}}, c.generation)
	if err == nil {
		t.Fatal("expected apply failure")
	}
	if !reflect.DeepEqual(e.calls, []string{"apply"}) {
		t.Fatal(e.calls)
	}
	if len(array(c.op.Journal.Values()["closures"])) != 1 {
		t.Fatal("lost retry intent")
	}
}
func TestStaleProbeCannotChangeReplacementLane(t *testing.T) {
	c, e, _, _ := testCore(t, map[string]any{"lines": testLines()})
	for _, l := range c.lanes {
		l.health.Up = ptr(true)
		l.health.HadAddress = ptr(true)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	pending := []func(){}
	c.op.Background = func(f func()) { pending = append(pending, f) }
	e.probe = func(engine.ProbeRequest) engine.ProbeResult { return engine.ProbeResult{Outcome: engine.LineFailed} }
	for _, l := range c.lanes {
		l.probeAt = nil
	}
	c.scheduleProbes(context.Background(), nil)
	if len(pending) != 2 {
		t.Fatalf("expected two delayed probes, got %d", len(pending))
	}
	c.lanes["a1"].generation++
	for _, f := range pending {
		f()
	}
	if c.lanes["a1"].health.Offline || c.lanes["a1"].health.ProbeFails != 0 {
		t.Fatal("old probe changed current line")
	}
}
func TestQueueFailureAndCancellationDoNotPoisonFollowingItems(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q := newQueue(ctx)
	if err := q.Do(ctx, func() error { return errors.New("failed") }); err == nil {
		t.Fatal("missing failure")
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if err := q.Do(canceled, func() error { t.Fatal("ran canceled task"); return nil }); err == nil {
		t.Fatal("missing cancellation")
	}
	if err := q.Do(ctx, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPBoundaryWithoutOpeningSocket(t *testing.T) {
	c, _, _, _ := testCore(t, map[string]any{})
	h := &HTTP{Core: c, Port: 47821, Token: strings.Repeat("a", 48)}
	for _, tc := range []struct {
		name, method, path, host, origin, token, body string
		status                                        int
	}{{"ping", "GET", "/api/ping", "127.0.0.1:47821", "", h.Token, "", 200}, {"host", "GET", "/api/ping", "evil.invalid", "", h.Token, "", 403}, {"origin", "POST", "/api/routing", "127.0.0.1:47821", "https://evil.invalid", h.Token, `{}`, 403}, {"token", "GET", "/api/state", "localhost:47821", "", "wrong", "", 401}, {"large", "POST", "/api/settings", "localhost:47821", "", h.Token, strings.Repeat(" ", 65537), 400}, {"invalid", "POST", "/api/settings", "localhost:47821", "", h.Token, "{", 400}, {"missing", "GET", "/api/missing", "localhost:47821", "", h.Token, "", 404}, {"ui", "GET", "/", "localhost:47821", "", "", "", 200}} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			r.Host = tc.host
			r.Header.Set("X-Token", tc.token)
			r.Header.Set("Origin", tc.origin)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("%d: %s", w.Code, w.Body.String())
			}
			if tc.name == "ui" && !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
				t.Fatal("missing CSP")
			}
		})
	}
}

func TestStateNonFiniteRatesAreNull(t *testing.T) {
	c, _, _, _ := testCore(t, map[string]any{})
	c.tracker = &seededTracker{rows: []apps.Row{{Key: "unknown", Path: "", Rate: apps.Rate{Down: math.NaN(), Up: math.Inf(1)}, LineDown: map[string]float64{}, SortScore: math.Inf(-1), Connections: map[string]int{}}}}
	b, err := js.Marshal(c.State())
	if err != nil {
		t.Fatal(err)
	}
	v, err := js.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	row := js.Object(array(js.Object(v)["apps"])[0])
	rate := js.Object(row["rate"])
	if rate["down"] != nil || rate["up"] != nil || row["sortScore"] != nil {
		t.Fatalf("non-finite values must be null: %s", b)
	}
}

func TestConcurrentStateSettingsAndCounters(t *testing.T) {
	c, _, clock, _ := testCore(t, map[string]any{"lines": testLines()})
	c.adapters = []map[string]any{{"alias": "Ethernet", "ipv4s": []any{"192.0.2.1"}}, {"alias": "Wi-Fi", "ipv4s": []any{"192.0.2.2"}}}
	c.routes = []map[string]any{{"interfaceAddress": "192.0.2.1"}, {"interfaceAddress": "192.0.2.2"}}
	c.routesAt = c.now()
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			if _, err := js.Marshal(c.State()); err != nil {
				t.Error(err)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 25; i++ {
			clock.advance(1000)
			c.HelperLine([]byte(fmt.Sprintf(`{"adapters":[{"alias":"Ethernet","rx":%d,"tx":0}]}`, i*100)))
			if err := c.Poll(context.Background()); err != nil {
				t.Error(err)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 15; i++ {
			if _, err := c.Action(context.Background(), "POST", "/api/lines/update", map[string]any{"id": "b2", "label": fmt.Sprintf("Phone %d", i)}); err != nil {
				t.Error(err)
			}
		}
	}()
	wg.Wait()
}

func TestConnectionReplyFromStoppedGenerationIsDiscarded(t *testing.T) {
	c, e, _, _ := testCore(t, map[string]any{"lines": testLines()})
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	e.readConnections = func(context.Context) ([]engine.Connection, error) {
		close(entered)
		<-release
		return []engine.Connection{{Connection: apps.Connection{ID: "late", Chains: []string{"line-b2"}, Download: 100000}}}, nil
	}
	done := make(chan error, 1)
	go func() { done <- c.Poll(context.Background()) }()
	<-entered
	if err := c.Routing(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.connections) != 0 || len(c.tracker.Snapshot(nil)) != 0 {
		t.Fatal("late engine reply repopulated a stopped generation")
	}
}

func TestFailedStatisticsReadDoesNotPreventFailover(t *testing.T) {
	c, e, clock, _ := testCore(t, map[string]any{"lines": testLines()})
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.readConnections = func(context.Context) ([]engine.Connection, error) {
		return nil, errors.New("statistics endpoint stalled")
	}
	c.adapters[0]["ipv4s"] = []any{}
	for i := 0; i < 2; i++ {
		clock.advance(1000)
		_ = c.Poll(context.Background())
	}
	if got := e.Snapshot().Policy.Lanes["a1"]; got != "b2" {
		t.Fatalf("statistics failure left dead main lane on %q", got)
	}
}

func TestSupervisorDoesNotRepeatACompletedRebind(t *testing.T) {
	c, e, clock, _ := testCore(t, map[string]any{"lines": testLines()})
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.calls = nil
	items := testLines()
	items[0].Alias = "Renamed"
	c.mu.Lock()
	c.values["lines"] = items
	c.mu.Unlock()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	clock.beforeNow = func() { once.Do(func() { close(entered); <-release }) }
	done := make(chan error, 1)
	go func() { done <- c.Supervise(context.Background()) }()
	<-entered
	e.mu.Lock()
	updated := e.s.Policy
	updated.Lines = items
	e.s.Policy = updated
	e.s.StartedWith = &updated
	e.mu.Unlock()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(e.calls) != 0 {
		t.Fatalf("supervisor restarted an already rebound engine: %v", e.calls)
	}
}

func TestRealTrafficNeedsTwoDifferentNewHosts(t *testing.T) {
	c, e, clock, _ := testCore(t, map[string]any{"lines": testLines()})
	c.adapters = []map[string]any{{"alias": "Ethernet", "ipv4s": []any{"192.0.2.1"}}, {"alias": "Wi-Fi", "ipv4s": []any{"192.0.2.2"}}}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls := 0
	e.probe = func(engine.ProbeRequest) engine.ProbeResult { calls++; return engine.ProbeResult{Outcome: engine.OK} }
	start := clock.Now().Add(-time.Second).Format(time.RFC3339Nano)
	connections := []engine.Connection{{Connection: apps.Connection{ID: "one", Start: start, Download: 1, Chains: []string{"line-a1"}}, Host: "one.example"}, {Connection: apps.Connection{ID: "two", Start: start, Download: 1, Chains: []string{"line-a1"}}, Host: "two.example"}}
	c.lanes["a1"].probeAt = nil
	c.lanes["b2"].probeAt = ptr(c.now())
	c.scheduleProbes(context.Background(), connections)
	if calls != 0 {
		t.Fatal("real traffic did not suppress endpoint probes")
	}
	c.lanes["a1"].probeAt = nil
	c.scheduleProbes(context.Background(), nil)
	if calls != 0 {
		t.Fatal("recent closed connections were forgotten")
	}
	c.evidence = map[string]map[string]int64{}
	connections[1].Host = "one.example"
	c.lanes["a1"].probeAt = nil
	c.scheduleProbes(context.Background(), connections)
	if calls == 0 {
		t.Fatal("one host was counted as two")
	}
	connections[1].Host = "two.example"
	clock.advance(31000)
	calls = 0
	c.lanes["a1"].probeAt = nil
	c.lanes["b2"].probeAt = ptr(c.now())
	c.scheduleProbes(context.Background(), connections)
	if calls == 0 {
		t.Fatal("expired real-traffic evidence suppressed checks")
	}
}

func TestFailedQuickCheckUsesTwoOtherOperatorsInParallel(t *testing.T) {
	c, e, _, _ := testCore(t, map[string]any{"lines": testLines()})
	c.adapters[0]["index"] = float64(42)
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.lanes["a1"].target = ptr("b2")
	c.lanes["a1"].operator = 0
	c.lanes["a1"].probeAt = nil
	c.lanes["b2"].probeAt = ptr(c.now())
	entered, release := make(chan engine.ProbeRequest, 2), make(chan struct{})
	e.probe = func(r engine.ProbeRequest) engine.ProbeResult {
		if r.Quick {
			if r.Target != "1.1.1.1:443" {
				t.Error("wrong quick operator")
			}
			return engine.ProbeResult{Outcome: engine.LineFailed}
		}
		entered <- r
		<-release
		return engine.ProbeResult{Outcome: engine.LineFailed}
	}
	done := make(chan struct{})
	go func() { c.scheduleProbes(context.Background(), nil); close(done) }()
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case r := <-entered:
			seen[r.Target] = true
			if r.Index != 42 || r.Line != "a1" {
				t.Errorf("probe followed a lane instead of its physical line: %+v", r)
			}
		case <-time.After(2 * time.Second):
			close(release)
			<-done
			t.Fatal("full checks were serialized")
		}
	}
	close(release)
	<-done
	if !seen["8.8.8.8:443"] || !seen["9.9.9.9:443"] {
		t.Fatal(seen)
	}
}

func TestDownLineNeedsHTTPSDespiteRecentTraffic(t *testing.T) {
	c, e, clock, _ := testCore(t, map[string]any{"lines": testLines()})
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	l := c.lanes["a1"]
	l.health.Up = ptr(false)
	l.health.Offline = true
	l.probeAt = nil
	c.lanes["b2"].probeAt = ptr(c.now())
	var full atomic.Int32
	e.probe = func(r engine.ProbeRequest) engine.ProbeResult {
		if r.Quick {
			t.Error("quick check attempted to recover a down line")
		} else {
			full.Add(1)
		}
		return engine.ProbeResult{Outcome: engine.OK}
	}
	start := clock.Now().Format(time.RFC3339Nano)
	connections := []engine.Connection{{Connection: apps.Connection{ID: "one", Start: start, Download: 1, Chains: []string{"line-a1"}}, Host: "one.example"}, {Connection: apps.Connection{ID: "two", Start: start, Download: 1, Chains: []string{"line-a1"}}, Host: "two.example"}}
	c.scheduleProbes(context.Background(), connections)
	if full.Load() != 2 {
		t.Fatalf("expected two full operator checks, got %d", full.Load())
	}
}

type seededTracker struct{ rows []apps.Row }

func (s *seededTracker) Reset()                                       {}
func (s *seededTracker) Ingest([]apps.Connection, int64)              {}
func (s *seededTracker) Snapshot(apps.Pins) []apps.Row                { return s.rows }
func (s *seededTracker) LineRate(string) apps.Rate                    { return apps.Rate{} }
func (s *seededTracker) ConnectionIDsOffLine(string, string) []string { return nil }
func (s *seededTracker) IdentityOf(string) string                     { return "" }

func TestStateMatchesEveryFrozenTrayScenario(t *testing.T) {
	input, err := os.ReadFile("../../tests/oracle/fixtures/tray-inputs.json")
	if err != nil {
		t.Fatal(err)
	}
	var scenarios map[string]json.RawMessage
	if err := json.Unmarshal(input, &scenarios); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../tests/oracle/fixtures/node.json")
	if err != nil {
		t.Fatal(err)
	}
	var frozen struct {
		States map[string]struct {
			Body json.RawMessage `json:"body"`
		} `json:"states"`
	}
	if err := json.Unmarshal(b, &frozen); err != nil {
		t.Fatal(err)
	}
	if len(scenarios) != len(frozen.States) {
		t.Fatal("scenario count changed")
	}
	for name, raw := range scenarios {
		t.Run(name, func(t *testing.T) {
			c, e, clock, _ := testCore(t, map[string]any{})
			v, err := js.Decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			scenario := js.Object(v)
			lineRaw, _ := json.Marshal(scenario["lines"])
			var items []lines.Line
			if err := json.Unmarshal(lineRaw, &items); err != nil {
				t.Fatal(err)
			}
			c.values["lines"] = items
			c.syncLanesLocked()
			c.elevated = true
			c.wanted = js.Object(scenario["routing"])["wanted"] == true
			e.s.Status = js.Text(js.Object(scenario["routing"])["status"])
			e.s.StartedWith = &engine.Policy{Lines: items}
			e.s.Policy = engine.Policy{Lines: items, Combine: js.Object(scenario["combine"])["on"] == true, Shares: lines.Shares{}}
			c.policy = float64(1)
			for _, raw := range array(scenario["lines"]) {
				v := js.Object(raw)
				id := js.Text(v["id"])
				l := c.lanes[id]
				l.health.Up = ptr(v["connected"] == true)
				if v["problem"] != nil {
					l.health.Reason = ptr(js.Text(v["problem"]))
				}
				if v["ping"] != nil {
					l.delay = ptr(js.Number(v["ping"]))
				}
				if v["target"] != nil {
					l.target = ptr(js.Text(v["target"]))
				}
				c.connections[id] = int(js.Number(v["connections"]))
				u := js.Object(v["usage"])
				at, err := time.Parse(time.RFC3339Nano, js.Text(u["periodStart"]))
				if err != nil {
					t.Fatal(err)
				}
				c.usage.Lines[id] = usage.Entry{Bytes: js.Number(u["bytes"]), PeriodStart: float64(at.UnixMilli())}
				if v["exhausted"] == true {
					c.exhausted[id] = true
				}
				if v["share"] != nil {
					e.s.Policy.Shares = append(e.s.Policy.Shares, lines.Share{ID: id, Value: js.Number(v["share"])})
				}
				rate := js.Object(v["rate"])
				c.meters[js.Text(v["alias"])] = meter{at: clock.Now().UnixMilli(), rate: &apps.Rate{Down: js.Number(rate["down"]), Up: js.Number(rate["up"])}}
				c.adapters = append(c.adapters, map[string]any{"alias": v["alias"], "kind": v["kind"], "ssid": v["ssid"], "connected": v["connected"]})
			}
			tracker := &seededTracker{}
			pins := apps.Pins{}
			for _, raw := range array(scenario["apps"]) {
				v := js.Object(raw)
				path := js.Text(v["path"])
				var pin *string
				if v["line"] != nil {
					pin = ptr(js.Text(v["line"]))
					pins = append(pins, apps.Pin{Path: path, LineID: *pin})
				}
				home := items[0].ID
				if pin != nil {
					home = *pin
				}
				rate := js.Object(v["rate"])
				tracker.rows = append(tracker.rows, apps.Row{Key: apps.AppKey(path), Path: path, Line: pin, Rate: apps.Rate{Down: js.Number(rate["down"]), Up: js.Number(rate["up"])}, LineDown: map[string]float64{home: js.Number(rate["down"])}, SortScore: js.Number(v["sortScore"]), Connections: map[string]int{}})
			}
			c.values["appLines"] = pins
			c.tracker = tracker
			request := httptest.NewRequest("GET", "http://127.0.0.1:47821/api/state", nil)
			request.Header.Set("X-Token", "contract-token")
			recorder := httptest.NewRecorder()
			(&HTTP{Core: c, Port: 47821, Token: "contract-token"}).ServeHTTP(recorder, request)
			if recorder.Code != 200 {
				t.Fatalf("state HTTP status %d", recorder.Code)
			}
			actual := recorder.Body.Bytes()
			got, err := js.Decode(actual)
			if err != nil {
				t.Fatal(err)
			}
			want, err := js.Decode(frozen.States[name].Body)
			if err != nil {
				t.Fatal(err)
			}
			operatorStateExpectation(js.Object(want), false)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("state contract differs\ngot: %s\nwant: %s", actual, frozen.States[name].Body)
			}
		})
	}
}
