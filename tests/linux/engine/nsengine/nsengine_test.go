package nsengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/tests/linux/engine"
)

// runtime is the smallest protocol.Runtime: the flow table alone.
type runtime struct{ table *flows.Table }

func (r runtime) Start(_ context.Context, v policy.Revision) (policy.Applied, error) {
	return r.table.Apply(v)
}
func (r runtime) Apply(_ context.Context, v policy.Revision) (policy.Applied, error) {
	return r.table.Apply(v)
}
func (r runtime) Stop(context.Context) error {
	r.table.Unload()
	r.table.CloseAll()
	return nil
}

// rig is a driver whose transport reaches an in-memory protocol.Server, each
// request and reply going through JSON as on the socket. seen records every
// error text the server sent.
type rig struct {
	d     *Driver
	table *flows.Table
	mu    sync.Mutex // sessions renew from their own goroutines
	seen  map[string]bool
}

func newRig() *rig {
	table := flows.New(flows.Defaults(), nil)
	srv := protocol.New(runtime{table}, table, nil)
	r := &rig{d: New("netswitch-engine"), table: table, seen: map[string]bool{}}
	r.d.call = func(ctx context.Context, req protocol.Request) ([]byte, error) {
		line, err := json.Marshal(req)
		if err != nil {
			return nil, err
		}
		decoded, err := protocol.Decode(line)
		if err != nil {
			return nil, fmt.Errorf("the engine wouldn't read %s: %w", line, err)
		}
		reply := srv.Handle(ctx, decoded)
		if reply.Error != "" {
			r.mu.Lock()
			r.seen[reply.Error] = true
			r.mu.Unlock()
		}
		return json.Marshal(reply)
	}
	r.d.addresses = func(_ context.Context, _, iface string) ([]netip.Addr, error) {
		return map[string][]netip.Addr{
			"eth-a": {netip.MustParseAddr("192.168.1.2")},
			"eth-b": {netip.MustParseAddr("192.168.2.2")},
		}[iface], nil
	}
	return r
}

const (
	bravo = "/opt/nsapps/bravo/nsapp"
	alpha = "/opt/nsapps/alpha/nsapp"
)

func config() engine.Config {
	return engine.Config{
		Lines:  []engine.Line{{ID: "a", Interface: "eth-a"}, {ID: "b", Interface: "eth-b"}},
		Policy: engine.Policy{Pins: []engine.Pin{{App: engine.App{Path: bravo}, Line: "b"}}},
	}
}

func refused(t *testing.T, err error, want engine.RefusalCode, what string) {
	t.Helper()
	var r *engine.Refusal
	if !errors.As(err, &r) || r.Code != want {
		t.Errorf("%s: got %v, want a %s refusal", what, err, want)
	}
}

func (r *rig) attach(t *testing.T) *Session {
	t.Helper()
	c, err := r.d.Attach(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s := c.(*Session)
	t.Cleanup(func() { s.SetAutoRenew(false) })
	return s
}

// open admits n flows from bravo through the table, as forwarding would.
func (r *rig) open(t *testing.T, n int) {
	t.Helper()
	for i := range n {
		ticket, err := r.table.Begin("tcp", platform.Tuple{
			Source:      netip.AddrPortFrom(netip.MustParseAddr("198.18.0.1"), uint16(30000+i)),
			Destination: netip.MustParseAddrPort("198.51.100.10:7002"),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ticket.Resolve(platform.Owner{PID: 4242, StartTime: 7, Path: bravo, AppID: bravo}); err != nil {
			t.Fatal(err)
		}
		ticket.Add(100, 1000)
	}
}

// sessionScenario walks a control session through every lifecycle command
// and every refusal the protocol defines.
func sessionScenario(t *testing.T, r *rig) {
	ctx := context.Background()
	hello, err := r.d.Hello(ctx)
	if err != nil || hello.InstanceID == "" || hello.Applied != nil || hello.Epoch != 0 {
		t.Fatalf("hello before attach: %+v, %v", hello, err)
	}
	refused(t, r.d.do(ctx, protocol.Request{ID: "early", Method: "predict", Instance: hello.InstanceID, App: bravo}, nil),
		engine.RefusedFenced, "a command before any attach")

	s := r.attach(t)
	if s.Epoch() != 1 || s.InstanceID() != hello.InstanceID {
		t.Fatalf("the engine hands out epoch 1 to the first controller, got %d", s.Epoch())
	}
	_, err = s.Predict(ctx, engine.App{Path: bravo})
	refused(t, err, engine.RefusedNotRunning, "predict before start")

	first, err := s.Start(ctx, 1, config())
	if err != nil || first.N != 1 || first.Hash == "" || first.Point == 0 {
		t.Fatalf("start revision 1: %+v, %v", first, err)
	}
	again, err := s.Apply(ctx, 1, config())
	if err != nil || again.Revision != first.Revision {
		t.Errorf("the same n and hash again is a success: %+v, %v", again, err)
	}
	other := config()
	other.Policy.IPv6 = true
	_, err = s.Apply(ctx, 1, other)
	refused(t, err, engine.RefusedConflict, "the same n with another hash")
	second, err := s.Apply(ctx, 2, other)
	if err != nil || second.N != 2 || second.Point <= first.Point {
		t.Fatalf("revision 2: %+v, %v", second, err)
	}
	_, err = s.Apply(ctx, 1, config())
	refused(t, err, engine.RefusedStale, "a lower n")
	bad := s.request("apply")
	bad.Revision = &policy.Revision{N: 9, Hash: "not the hash", Config: wireConfig(config(), []platform.Line{{ID: "a"}})}
	refused(t, r.d.do(ctx, bad, nil), engine.RefusedInvalidRevision, "a hash that isn't the config's")
	if h, err := r.d.Hello(ctx); err != nil || h.Applied == nil || h.Applied.N != 2 || h.Epoch != 1 {
		t.Errorf("hello reports revision 2 in effect and epoch 1: %+v, %v", h, err)
	}
	if p, err := s.Predict(ctx, engine.App{Path: bravo}); err != nil || p.Line != "b" || p.Distribution != nil {
		t.Errorf("predict for pinned bravo: %+v, %v", p, err)
	}

	_, err = s.CloseFlows(ctx, "op-1", engine.Selector{}, 0)
	refused(t, err, engine.RefusedSelector, "an empty selector")
	_, err = s.CloseFlows(ctx, "op-2", engine.Selector{App: bravo}, 0)
	refused(t, err, engine.RefusedSelector, "an app without notLine")
	outside := s.request("closeFlows")
	outside.OpID, outside.Selector = "op-3", flows.Selector{App: bravo, OutsideOnly: true}
	refused(t, r.d.do(ctx, outside, nil), engine.RefusedSelector, "outside connections")
	if res, err := s.CloseFlows(ctx, "op-4", engine.Selector{Line: "b"}, 0); err != nil || res != (engine.CloseResult{}) {
		t.Errorf("closing line b with nothing open: %+v, %v", res, err)
	}
	_, err = s.CloseFlows(ctx, "op-4", engine.Selector{Line: "a"}, 0)
	refused(t, err, engine.RefusedOperationConflict, "an operation id reused with another selector")

	shared := config()
	shared.Policy.Combine = true
	shared.Policy.Shares = map[engine.LineID]float64{"a": 2.0 / 3, "b": 1.0 / 3}
	if _, err := s.Apply(ctx, 3, shared); err != nil {
		t.Fatal(err)
	}
	dist, err := s.Predict(ctx, engine.App{Path: alpha})
	if err != nil || len(dist.Distribution) != 2 || dist.Distribution["a"] < 0.66 || dist.Distribution["a"] > 0.67 {
		t.Errorf("predict for unpinned alpha while combining 2:1: %+v, %v", dist, err)
	}
	_, err = s.CloseFlows(ctx, "op-5", engine.Selector{App: alpha, NotLine: "a"}, 0)
	refused(t, err, engine.RefusedSelector, "reconnecting a shared app")

	fresh := r.attach(t)
	if fresh.Epoch() != 2 {
		t.Fatalf("a second controller gets epoch 2, got %d", fresh.Epoch())
	}
	refused(t, s.Renew(ctx), engine.RefusedFenced, "the old controller's renewal")
	_, err = s.Flows(ctx, "")
	refused(t, err, engine.RefusedFenced, "the old controller's command")
	if err := fresh.Renew(ctx); err != nil {
		t.Errorf("the new controller renews: %v", err)
	}
	if err := r.d.do(ctx, fresh.request("bogus"), nil); err == nil || errors.As(err, new(*engine.Refusal)) {
		t.Errorf("an unknown failure must not read as a refusal: %v", err)
	}
	refused(t, r.d.do(ctx, protocol.Request{ID: "picked", Method: "attach", Instance: hello.InstanceID, Epoch: 7}, nil),
		engine.RefusedAttach, "an attach that picks its own epoch")

	if err := fresh.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	refused(t, fresh.Renew(ctx), engine.RefusedLapsed, "a renewal once the engine is stopping")
}

func TestSessionAgainstTheProtocol(t *testing.T) {
	sessionScenario(t, newRig())
}

func TestRefusalsMatchTheServer(t *testing.T) {
	r := newRig()
	sessionScenario(t, r)

	// Capacity: a fifth flow snapshot while four are open.
	c := newRig()
	ctx := context.Background()
	s := c.attach(t)
	if _, err := s.Start(ctx, 1, config()); err != nil {
		t.Fatal(err)
	}
	c.open(t, 100)
	for i := range 4 {
		if page, err := s.Flows(ctx, ""); err != nil || page.Next == "" {
			t.Fatalf("snapshot %d: %v (next %q)", i+1, err, page.Next)
		}
	}
	_, err := s.Flows(ctx, "")
	refused(t, err, engine.RefusedCapacity, "a fifth snapshot at once")
	c.mu.Lock()
	r.mu.Lock()
	defer r.mu.Unlock()
	for text := range c.seen {
		r.seen[text] = true
	}
	c.mu.Unlock()

	// Every text the table calls a refusal must be one the server produced.
	var missing []string
	for text := range refusals {
		if !r.seen[text] {
			missing = append(missing, text)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("refusals the server never produced (reworded or gone?): %q", missing)
	}
}

func TestAttachAdoptsTheNewSession(t *testing.T) {
	ctx := context.Background()
	r := newRig()
	first := r.attach(t)
	if r.d.Session() != engine.Controller(first) || !first.renewing() {
		t.Fatal("the first attach is the driver's session, and renews itself")
	}
	if _, err := first.Start(ctx, 1, config()); err != nil {
		t.Fatal(err)
	}
	r.d.cfg = config()
	fresh := r.attach(t)
	if r.d.Session() != engine.Controller(fresh) {
		t.Fatal("after a reattach the driver must use the new session")
	}
	if first.renewing() || !fresh.renewing() {
		t.Errorf("the fenced session stops renewing and the new one renews (old %v, new %v)", first.renewing(), fresh.renewing())
	}
	// Against a fencing engine, everything the driver does now must go
	// through the new session.
	p := config().Policy
	p.IPv6 = true
	if err := r.d.Apply(ctx, p); err != nil {
		t.Fatalf("apply after the reattach: %v", err)
	}
	if err := r.d.SetLanes(ctx, map[engine.LineID]engine.LineID{"b": "a"}); err != nil {
		t.Fatalf("lanes after the reattach: %v", err)
	}
	if _, err := r.d.Flows(ctx); err != nil {
		t.Fatalf("flows after the reattach: %v", err)
	}
	if _, err := r.d.CloseFlows(ctx, engine.Selector{Line: "b"}); err != nil {
		t.Fatalf("closeFlows after the reattach: %v", err)
	}
	// Stop reaches the engine through the new session. This injected transport
	// has no OS process to wait for.
	if err := r.d.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if fresh.renewing() {
		t.Error("a stopped session doesn't renew")
	}
	refused(t, fresh.Renew(ctx), engine.RefusedLapsed, "a renewal after the driver stopped the engine")
}

func TestFlowsPageAndConvert(t *testing.T) {
	ctx := context.Background()
	r := newRig()
	s := r.attach(t)
	start, err := s.Start(ctx, 1, config())
	if err != nil {
		t.Fatal(err)
	}
	r.open(t, 100)
	first, err := s.Flows(ctx, "")
	if err != nil || len(first.Flows) == 0 || first.Next == "" {
		t.Fatalf("first page: %d flows, next %q, %v", len(first.Flows), first.Next, err)
	}
	f := first.Flows[0]
	if f.App != bravo || f.AppID != bravo || f.PID != 4242 || f.Protocol != "tcp" || f.Lane != "b" || f.Line != "b" ||
		f.Revision != 1 || f.Epoch != s.Epoch() || f.Point <= start.Point || f.Destination.Port() != 7002 || f.Source.Addr().String() != "198.18.0.1" {
		t.Errorf("a flow as the suite sees it: %+v", f)
	}
	r.d.session = s
	all, err := r.d.Flows(ctx)
	if err != nil || len(all) != 100 {
		t.Fatalf("every page: %d flows, %v", len(all), err)
	}
	ids := map[string]bool{}
	for _, f := range all {
		ids[f.ID] = true
	}
	if len(ids) != 100 {
		t.Errorf("100 flows listed once each, got %d distinct", len(ids))
	}
	res, err := s.CloseFlows(ctx, "close-b", engine.Selector{Line: "b"}, 0)
	if err != nil || res.Closed != 100 {
		t.Errorf("closing line b: %+v, %v", res, err)
	}
	totals, err := s.Totals(ctx)
	if err != nil || totals.PerApp[bravo].Down != 100*1000 || totals.PerLine["b"].Up != 100*100 {
		t.Errorf("totals: %+v, %v", totals, err)
	}
	stats, err := s.Stats(ctx)
	if err != nil || stats.Flows != 100 || stats.Admitted != 100 {
		t.Errorf("stats: %+v, %v", stats, err)
	}
}

func TestStatsShapes(t *testing.T) {
	runtimeShape := `{"engine":{"flows":{"Flows":3,"Handshakes":1,"TCPBytes":65536,"Admitted":9,"LookupCount":4,"LookupNanoseconds":8000000,"LookupAmbiguous":1,"EventsDropped":2},"tunDropped":5,"fatal":"x"},"eventsDropped":1}`
	s, err := decodeStats([]byte(runtimeShape))
	if err != nil || s.Flows != 3 || s.Handshakes != 1 || s.TCPBytes != 65536 || s.Admitted != 9 || s.LookupAmbiguous != 1 ||
		s.LookupMean().Milliseconds() != 2 || s.EventsDropped != 3 || s.Counters["tunDropped"] != 5 {
		t.Errorf("the engine runtime's stats: %+v, %v", s, err)
	}
	bare, err := decodeStats([]byte(`{"engine":{"Flows":2,"UDP":1},"eventsDropped":0}`))
	if err != nil || bare.Flows != 2 || bare.UDP != 1 {
		t.Errorf("a bare table's stats: %+v, %v", bare, err)
	}
}

func TestUnconnectedDriverRefusesCommands(t *testing.T) {
	d := New("netswitch-engine")
	if _, err := d.Hello(context.Background()); !errors.Is(err, errNoSession) {
		t.Fatalf("without a control socket the driver must report not connected, got %v", err)
	}
	if err := d.Start(context.Background(), engine.Env{}, config()); err == nil {
		t.Fatalf("start: %v", err)
	}
}
