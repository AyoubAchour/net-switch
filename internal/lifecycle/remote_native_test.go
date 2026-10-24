package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apppath"
	"github.com/AyoubAchour/net-switch/internal/apps"
	ce "github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/host"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/internal/lines"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/internal/service"
)

// nativeRuntime stands in for the engine behind the real protocol server: a
// real flow table, a live state and a configured prober. No TUN, no service.
type nativeRuntime struct {
	table   *flows.Table
	state   atomic.Value
	started time.Time
	starts  atomic.Int64
}

func (r *nativeRuntime) Start(_ context.Context, v policy.Revision) (policy.Applied, error) {
	r.starts.Add(1)
	a, err := r.table.Apply(v)
	if err == nil {
		r.state.Store("on")
	}
	return a, err
}
func (r *nativeRuntime) Apply(_ context.Context, v policy.Revision) (policy.Applied, error) {
	return r.table.Apply(v)
}
func (r *nativeRuntime) Stop(context.Context) error {
	r.table.Unload()
	r.table.CloseAll()
	r.state.Store("off")
	return nil
}
func (r *nativeRuntime) LiveState() (string, time.Time) {
	s, _ := r.state.Load().(string)
	if s == "" {
		s = "off"
	}
	return s, r.started
}

type nativeProber struct {
	kind func(platform.ProbeRequest) string
}

func (p nativeProber) Probe(context.Context, string, string) (platform.ProbeResult, error) {
	return platform.ProbeResult{}, errors.New("named operators are not used by the native client")
}
func (p nativeProber) ProbeConfigured(_ context.Context, _ string, r platform.ProbeRequest) (platform.ProbeResult, error) {
	kind := "full"
	if r.Quick {
		kind = "quick"
	}
	if p.kind != nil {
		kind = p.kind(r)
	}
	latency := 18.5
	return platform.ProbeResult{OK: true, Kind: kind, Outcome: "ok", LatencyMS: &latency}, nil
}

type nativeFixture struct {
	server  *protocol.Server
	runtime *nativeRuntime
	remote  *Remote
	status  service.Status
	outcome host.Outcome
}

func newNativeFixture(t *testing.T, prober platform.Prober) *nativeFixture {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	table := flows.New(flows.Defaults(), nil)
	runtime := &nativeRuntime{table: table, started: time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)}
	server := protocol.New(runtime, table, prober)
	f := &nativeFixture{server: server, runtime: runtime}
	remote := NewRemote(ctx, func(string) {})
	remote.dial = func(context.Context, localipc.Endpoint) (*localipc.Conn, error) {
		left, right := net.Pipe()
		go server.Serve(ctx, left)
		return &localipc.Conn{ReadWriteCloser: right}, nil
	}
	remote.startService = func(context.Context, string) error { return nil }
	remote.queryService = func(string) (service.Status, error) { return f.status, nil }
	remote.waitStopped = func(context.Context, string) error { return nil }
	remote.outcome = func(string) (host.Outcome, error) { return f.outcome, nil }
	f.remote = remote
	f.status = service.Status{Running: true, PID: 4242}
	return f
}

func testPolicy() ce.Policy {
	return ce.Policy{
		Lines:    []lines.Line{{ID: "a1", Alias: "Ethernet"}, {ID: "b2", Alias: "Wi-Fi"}, {ID: "c3", Alias: "LTE"}},
		AppLines: apps.Pins{{Path: `C:\Games\game.exe`, LineID: "b2"}, {Path: `C:\Old\gone.exe`, LineID: "zz"}},
		Combine:  true,
		Shares:   lines.Shares{{ID: "a1", Value: 12}, {ID: "b2", Value: 8}},
		Lanes:    map[string]string{"a1": "a1", "b2": "b2", "c3": "a1"},
		Blocked:  []string{"c3"},
		IPv6:     false,
	}
}

func testRevision(n uint64) ce.Revision {
	p := testPolicy()
	return ce.Revision{Number: n, Hash: "control-hash-" + strconv.FormatUint(n, 10), Policy: p}
}

// On main, Control refuses any engine that does not advertise the sing-box
// adapter dialect ("engine swap is not installed"). This fails there.
func TestRemoteAttachesToTheNativeEngine(t *testing.T) {
	f := newNativeFixture(t, nativeProber{})
	ctx := context.Background()
	if err := f.remote.Attach(ctx, false); err != nil {
		t.Fatal("native attach refused:", err)
	}
	s := f.remote.Snapshot()
	if s.Status != "off" || s.Instance != f.server.Instance || s.PID == 0 {
		t.Fatalf("hello status not mapped: %+v", s)
	}
	if !f.remote.native {
		t.Fatal("dialect not detected as native")
	}
}

// The M2 dialer writes a one-byte impersonation primer before the JSON. The
// native host's pipe carries plain newline JSON and rejects that byte on the
// first exchange, which is what the installed proof hit on Windows. Control
// must therefore choose the dialer from the installation, not try both.
func TestNativeInstallDialsWithoutThePrimer(t *testing.T) {
	ctx := context.Background()
	primed := func(inner func(context.Context, localipc.Endpoint) (*localipc.Conn, error)) func(context.Context, localipc.Endpoint) (*localipc.Conn, error) {
		return func(ctx context.Context, e localipc.Endpoint) (*localipc.Conn, error) {
			c, err := inner(ctx, e)
			if err != nil {
				return nil, err
			}
			if _, err := c.Write([]byte{0}); err != nil { // the M2 primer byte
				c.Close()
				return nil, err
			}
			return c, nil
		}
	}
	// Through the real server's transport framing: the primer corrupts hello.
	f := newNativeFixture(t, nativeProber{})
	native := f.remote.dial
	f.remote.dial = primed(native)
	if err := f.remote.Attach(ctx, false); err == nil || !strings.Contains(err.Error(), "invalid character") {
		t.Fatal("native transport accepted the M2 primer byte", err)
	}
	f.remote.dial = native
	if err := f.remote.Attach(ctx, false); err != nil {
		t.Fatal("native dial without primer refused", err)
	}
	// The installation decides which dialer Control uses.
	for _, installed := range []bool{true, false} {
		r := NewRemote(ctx, func(string) {})
		chosen := ""
		r.dialNative = func(context.Context, localipc.Endpoint) (*localipc.Conn, error) {
			chosen = "native"
			return nil, errors.New("stop here")
		}
		r.dialAdapter = func(context.Context, localipc.Endpoint) (*localipc.Conn, error) {
			chosen = "adapter"
			return nil, errors.New("stop here")
		}
		r.nativeInstalled = func() (bool, error) { return installed, nil }
		_ = r.Attach(ctx, false)
		if (installed && chosen != "native") || (!installed && chosen != "adapter") {
			t.Fatalf("installed native=%t chose dialer %q", installed, chosen)
		}
	}
	r := NewRemote(ctx, func(string) {})
	r.nativeInstalled = func() (bool, error) { return false, errors.New("registry unreadable") }
	if err := r.Attach(ctx, false); err == nil || !strings.Contains(err.Error(), "which engine is installed") {
		t.Fatal("an unknown installation must not guess a dialer", err)
	}
}

func TestRemoteRefusesEnginesMissingRequiredCapabilities(t *testing.T) {
	if adapter, err := nativeDialect([]string{"revisions", "lease", "status"}); err == nil || adapter {
		t.Fatal("an engine without paged accounting was accepted", adapter, err)
	}
	if adapter, err := nativeDialect([]string{"singbox-adapter-v1", "revisions", "lease"}); err != nil || !adapter {
		t.Fatal("the temporary adapter dialect must stay selectable until its removal", adapter, err)
	}
}

// Pins must name the identity the engine itself gives the app: the platform's
// own normalisation (Linux keeps case), plus sandbox identities (Flatpak, Snap,
// AppImage) the engine reported for that path, which no path rule can derive.
func TestNativeRevisionUsesTheEnginesAppIdentity(t *testing.T) {
	if got := engineAppIdentityWith("/opt/Game/Game", apppath.Linux); got != "/opt/Game/Game" {
		t.Fatalf("Linux identity folded case or separators: %q", got)
	}
	if got := engineAppIdentityWith(`C:\Games\Game.exe`, apppath.Windows); got != apps.AppKey(`C:\Games\Game.exe`) {
		t.Fatalf("Windows identity differs from the owner lookup's key: %q", got)
	}
	// A pin stores the exact identity the user selected. Two Flatpaks share
	// /app/bin/game: pinning one must never pin the other or the plain path.
	rev := testRevision(3)
	rev.Policy.AppLines = apps.Pins{{Path: "flatpak:org.example.Game", LineID: "b2"}, {Path: "snap:other", LineID: "a1"}, {Path: "/opt/Plain/App", LineID: "a1"}}
	native, err := nativeRevision(rev)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"flatpak:org.example.Game": "b2", "snap:other": "a1", engineAppIdentity("/opt/Plain/App"): "a1"}
	if len(native.Config.AppLines) != len(want) {
		t.Fatalf("pins inferred or lost: %+v", native.Config.AppLines)
	}
	for id, line := range want {
		if native.Config.AppLines[id] != line {
			t.Fatalf("pin %q bound to %q, want %q (%+v)", id, native.Config.AppLines[id], line, native.Config.AppLines)
		}
	}
	if _, inferred := native.Config.AppLines["flatpak:org.example.Other"]; inferred {
		t.Fatal("an unrelated app sharing the path was pinned")
	}
	// The compiled hash depends on the durable revision alone, so a Control
	// restart (a fresh client, no flow history) produces the same revision.
	again, err := nativeRevision(rev)
	if err != nil || again.Hash != native.Hash {
		t.Fatal("sandbox pins changed the hash across a restart", err, again.Hash, native.Hash)
	}
	f := newNativeFixture(t, nativeProber{})
	ctx := context.Background()
	f.remote.Restore(&rev)
	if err := f.remote.Start(ctx, rev.Policy); err != nil {
		t.Fatal(err)
	}
	restarted := NewRemote(ctx, func(string) {})
	restarted.dial, restarted.queryService, restarted.outcome = f.remote.dial, f.remote.queryService, f.remote.outcome
	restarted.Restore(&rev)
	if err := restarted.Attach(ctx, false); err != nil {
		t.Fatal(err)
	}
	if s := restarted.Snapshot(); s.AppliedHash != rev.Hash || len(s.Policy.AppLines) != 3 {
		t.Fatalf("reattach after restart did not recognise its own revision with sandbox pins: %+v", s)
	}
}

func TestNativeRevisionIsAPureFunctionOfControlsPolicy(t *testing.T) {
	native, err := nativeRevision(testRevision(7))
	if err != nil {
		t.Fatal(err)
	}
	if native.N != 7 || native.Hash != policy.Hash(native.Config) {
		t.Fatal("revision number or hash wrong", native.N, native.Hash)
	}
	c := native.Config
	if len(c.Lines) != 3 || c.Lines[0].ID != "a1" || c.Lines[0].Interface != "Ethernet" || len(c.Lines[0].Addresses) != 0 || c.Lines[1].Interface != "Wi-Fi" {
		t.Fatalf("lines bind by alias: %+v", c.Lines)
	}
	// The key is this OS's engine identity (Windows folds case, Linux keeps
	// it), so the expectation comes from the same normaliser the client uses.
	if c.AppLines[engineAppIdentity(`C:\Games\game.exe`)] != "b2" || len(c.AppLines) != 1 {
		t.Fatalf("pins must use the engine's app key and drop unknown lines: %+v", c.AppLines)
	}
	if c.Shares["a1"] != 12_000_000 || c.Shares["b2"] != 8_000_000 || c.Lanes["c3"] != "a1" || len(c.Blocked) != 1 || c.Blocked[0] != "c3" || c.Combine != true {
		t.Fatalf("shares, lanes or blocked set lost: %+v", c)
	}
	if _, err := policy.Compile(native); err != nil {
		t.Fatal("the engine would refuse the compiled config:", err)
	}
	again, _ := nativeRevision(testRevision(7))
	if again.Hash != native.Hash {
		t.Fatal("translation is not deterministic")
	}
}

func TestNativeStartApplyAndSnapshotCarryPoints(t *testing.T) {
	f := newNativeFixture(t, nativeProber{})
	ctx := context.Background()
	rev := testRevision(1)
	f.remote.Restore(&rev)
	if err := f.remote.Start(ctx, rev.Policy); err != nil {
		t.Fatal(err)
	}
	s := f.remote.Snapshot()
	if s.Status != "on" || s.AppliedRevision != 1 || s.AppliedHash != rev.Hash || s.AppliedPoint == 0 || s.StartedWith == nil || len(s.Policy.Lines) != 3 {
		t.Fatalf("snapshot after start: %+v", s)
	}
	next := testRevision(2)
	next.Policy.IPv6 = true
	ack, err := f.remote.Apply(ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	if ack.Number != 2 || ack.Hash != next.Hash || ack.Point <= s.AppliedPoint || ack.Instance != f.server.Instance {
		t.Fatalf("acknowledgement lacks Control's hash or a later point: %+v", ack)
	}
	if after := f.remote.Snapshot(); after.AppliedPoint != ack.Point || !after.Policy.IPv6 {
		t.Fatalf("snapshot did not follow the apply: %+v", after)
	}
	// A refused start (engine already loaded a conflicting revision 2) stays
	// attached and leaves the engine's status in charge, not the transport.
	conflict := testRevision(2)
	f.remote.Restore(&conflict)
	if err := f.remote.Start(ctx, conflict.Policy); err == nil {
		t.Fatal("same number, different policy must be refused")
	}
	if f.remote.Snapshot().Status != "on" {
		t.Fatal("a refused apply disconnected or failed a live engine")
	}
}

func TestNativeFlowsKeepTheChainShapeAndEstablishedHostsOnly(t *testing.T) {
	f := newNativeFixture(t, nativeProber{})
	ctx := context.Background()
	rev := testRevision(1)
	f.remote.Restore(&rev)
	if err := f.remote.Start(ctx, rev.Policy); err != nil {
		t.Fatal(err)
	}
	tuple := platform.Tuple{Source: netip.MustParseAddrPort("198.18.0.2:40000"), Destination: netip.MustParseAddrPort("203.0.113.7:443")}
	established, err := f.runtime.table.Begin("tcp", tuple)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := established.Resolve(platform.Owner{AppID: "game", Path: `C:\Games\game.exe`}); err != nil {
		t.Fatal(err)
	}
	established.Established(netip.MustParseAddr("192.0.2.10"))
	established.Add(300, 700)
	tuple.Source = netip.MustParseAddrPort("198.18.0.2:40001")
	connecting, err := f.runtime.table.Begin("tcp", tuple)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connecting.Resolve(platform.Owner{AppID: "game", Path: `C:\Games\game.exe`}); err != nil {
		t.Fatal(err)
	}
	got, err := f.remote.Connections(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected two flows, got %+v", got)
	}
	byHost := map[string]ce.Connection{}
	for _, c := range got {
		byHost[c.Host] = c
	}
	e, ok := byHost["203.0.113.7"]
	if !ok || e.Metadata.ProcessPath != `C:\Games\game.exe` || e.Upload != 300 || e.Download != 700 || len(e.Chains) != 1 || e.Start == "" {
		t.Fatalf("established flow mapped wrongly: %+v", e)
	}
	// The combining policy spreads these unpinned flows over a1 and b2; the
	// record must name whichever line the engine chose, in Control's shape.
	line := apps.ConnectionLine(&e.Connection)
	if line == nil || (*line != "a1" && *line != "b2") {
		t.Fatalf("Control's line reader cannot read the native record: %+v", e.Chains)
	}
	if c, ok := byHost[""]; !ok || apps.ConnectionLine(&c.Connection) == nil {
		t.Fatalf("a connecting flow must list its line but no host: %+v", got)
	}
	// A later revision's apply point selects exactly the flows admitted before
	// it: closure by line with that point closes them and spares newer ones.
	next := testRevision(2)
	ack, err := f.remote.Apply(ctx, next)
	if err != nil || ack.Point == 0 {
		t.Fatal(ack, err)
	}
	tuple.Source = netip.MustParseAddrPort("198.18.0.2:40002")
	newer, err := f.runtime.table.Begin("tcp", tuple)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newer.Resolve(platform.Owner{AppID: "game", Path: `C:\Games\game.exe`}); err != nil {
		t.Fatal(err)
	}
	result, err := f.remote.CloseFlows(ctx, ce.CloseRequest{OperationID: "cut", Line: *line, StartedBeforePoint: ack.Point, Instance: f.server.Instance})
	if err != nil || result.Closed < 1 || result.Failed != 0 {
		t.Fatal("line closure by point", result, err)
	}
	// Without a forwarding goroutine the closed records stay listed as closing;
	// the newer flow, admitted after the point, must not be among them.
	page, err := f.runtime.table.Page("")
	if err != nil {
		t.Fatal(err)
	}
	closing := 0
	for _, r := range page.Flows {
		if r.Closing {
			closing++
		}
		if r.Source.Port() == 40002 && r.Closing {
			t.Fatal("closure by point touched the newer flow")
		}
	}
	if closing != result.Closed {
		t.Fatalf("closed %d but %d records are closing", result.Closed, closing)
	}
	if _, err := f.remote.CloseFlows(ctx, ce.CloseRequest{OperationID: "nocut", Line: "a1"}); err == nil {
		t.Fatal("a line closure without its cutoff was sent")
	}
	if _, err := f.remote.CloseFlows(ctx, ce.CloseRequest{OperationID: "ids", Instance: f.server.Instance, ConnectionIDs: []string{e.ID}}); err != nil {
		t.Fatal("closure by native flow ids", err)
	}
	if _, err := f.remote.CloseFlows(ctx, ce.CloseRequest{OperationID: "noinst", ConnectionIDs: []string{e.ID}}); err == nil {
		t.Fatal("a closure without its engine instance was sent")
	}
}

func TestNativeProbeCarriesKindAndInstance(t *testing.T) {
	f := newNativeFixture(t, nativeProber{kind: func(r platform.ProbeRequest) string { return "quick" }})
	ctx := context.Background()
	rev := testRevision(1)
	f.remote.Restore(&rev)
	if err := f.remote.Start(ctx, rev.Policy); err != nil {
		t.Fatal(err)
	}
	full := f.remote.Probe(ctx, ce.ProbeRequest{OperationID: "p1", Line: "a1", Target: "1.1.1.1:443"})
	if full.Outcome != ce.OK || full.Kind != "quick" || full.Instance != f.server.Instance || full.Delay == nil || *full.Delay != 18.5 {
		t.Fatalf("probe result not carried: %+v", full)
	}
	// An engine answering a quick check for a full request is visible to
	// Control's acceptance rule through Kind; the client reports, it does not
	// hide. The pure control tests prove the rejection.
	quick := f.remote.Probe(ctx, ce.ProbeRequest{OperationID: "p2", Line: "a1", Target: "1.1.1.1:443", Quick: true})
	if quick.Kind != "quick" {
		t.Fatalf("quick probe kind lost: %+v", quick)
	}
}

func TestNativeTotalsAndAcknowledgementOverTheWire(t *testing.T) {
	f := newNativeFixture(t, nativeProber{})
	ctx := context.Background()
	rev := testRevision(1)
	f.remote.Restore(&rev)
	if err := f.remote.Start(ctx, rev.Policy); err != nil {
		t.Fatal(err)
	}
	tuple := platform.Tuple{Source: netip.MustParseAddrPort("198.18.0.2:40000"), Destination: netip.MustParseAddrPort("203.0.113.7:443")}
	ticket, err := f.runtime.table.Begin("tcp", tuple)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ticket.Resolve(platform.Owner{AppID: "game"}); err != nil {
		t.Fatal(err)
	}
	ticket.Add(11, 22)
	ticket.Close()
	page, err := f.remote.Totals(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	var lineDown uint64
	for _, c := range page.Lines {
		lineDown += c.Down
	}
	if page.Instance != f.server.Instance || page.Receipt == "" || page.Cursor != "" || page.Apps["game"].Up != 11 || page.Apps["game"].Down != 22 || lineDown != 22 {
		t.Fatalf("totals page: %+v", page)
	}
	if err := f.remote.AckTotals(ctx, "ack-"+page.Receipt, page.Receipt); err != nil {
		t.Fatal("ack over the wire", err)
	}
	if err := f.remote.AckTotals(ctx, "ack-"+page.Receipt, page.Receipt); err != nil {
		t.Fatal("a repeated acknowledgement with the same opId must be idempotent", err)
	}
	after, err := f.remote.Totals(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, kept := after.Apps["game"]; kept {
		t.Fatal("acknowledged idle identity was not retired", after)
	}
	plain := NewRemote(ctx, func(string) {})
	if _, err := plain.Totals(ctx, ""); !errors.Is(err, ce.ErrNoAccounting) {
		t.Fatal("the adapter dialect must report that it has no accounting", err)
	}
}

// A closure Core checked against one instance must never reach a replacement:
// flow ids are per instance and a new engine reuses them.
func TestClosureIsFencedToItsOriginalInstance(t *testing.T) {
	f := newNativeFixture(t, nativeProber{})
	ctx := context.Background()
	rev := testRevision(1)
	f.remote.Restore(&rev)
	if err := f.remote.Start(ctx, rev.Policy); err != nil {
		t.Fatal(err)
	}
	tuple := platform.Tuple{Source: netip.MustParseAddrPort("198.18.0.2:40000"), Destination: netip.MustParseAddrPort("203.0.113.7:443")}
	ticket, err := f.runtime.table.Begin("tcp", tuple)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ticket.Resolve(platform.Owner{AppID: "game"}); err != nil {
		t.Fatal(err)
	}
	// The intent was recorded against an engine that has since been replaced
	// by the attached one; its flow id 1 now names an unrelated new flow.
	old := ce.CloseRequest{OperationID: "stale", Instance: "replaced-" + f.server.Instance, ConnectionIDs: []string{"1"}}
	if _, err := f.remote.CloseFlows(ctx, old); err == nil {
		t.Fatal("closure for a replaced instance was sent to the current engine")
	}
	page, err := f.runtime.table.Page("")
	if err != nil || len(page.Flows) != 1 || page.Flows[0].Closing {
		t.Fatal("the unrelated new flow was touched", page.Flows, err)
	}
	// Replacement between Core's check and the send: the request carries the
	// captured instance, so the engine itself fences it even without Core.
	f.remote.mu.Lock()
	f.remote.instance = "replaced-mid-closure"
	f.remote.mu.Unlock()
	if _, err := f.remote.CloseFlows(ctx, ce.CloseRequest{OperationID: "mid", Instance: "replaced-mid-closure", ConnectionIDs: []string{"1"}}); err == nil {
		t.Fatal("engine accepted a closure fenced to another instance")
	}
	page, _ = f.runtime.table.Page("")
	if len(page.Flows) != 1 || page.Flows[0].Closing {
		t.Fatal("the fenced closure closed a flow", page.Flows)
	}
}

// A native engine that failed or lost its adapter while Control was down is
// classified from its retained outcome at Control startup, before any hello.
func TestRetainedNativeExitIsClassifiedAtStartup(t *testing.T) {
	f := newNativeFixture(t, nativeProber{})
	data := t.TempDir()
	instance := "0123456789abcdef0123456789abcdef"
	// A plain write stands in for the service's ACL-protected durable save,
	// which needs the SYSTEM identity this pure test does not have.
	if _, err := host.Open(filepath.Join(data, "engine-state.json"), instance, func(r host.Record) error {
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(data, "engine-state.json"), b, 0600)
	}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	f.status = service.Status{Stopped: true, Cleanup: "complete", ExitKnown: true, ExitCode: 3}
	f.outcome = host.Outcome{Instance: instance, State: "complete", Reason: "adapter lost"}
	if err := f.remote.classifyRetainedExit(ctx, data); err != nil {
		t.Fatal(err)
	}
	if s := f.remote.Snapshot(); s.Status != "error" || s.Reason != ce.ReasonAdapterLost || s.FailureID != instance || s.Instance != instance {
		t.Fatalf("retained adapter loss not classified: %+v", s)
	}
	// A plain failure counts; the stand-in's exit-reason file is not involved.
	plain := newNativeFixture(t, nativeProber{})
	plain.status = service.Status{Stopped: true, Cleanup: "complete", ExitKnown: true, ExitCode: 1}
	plain.outcome = host.Outcome{Instance: instance, State: "complete", Reason: "failure"}
	if err := plain.remote.classifyRetainedExit(ctx, data); err != nil {
		t.Fatal(err)
	}
	if s := plain.remote.Snapshot(); s.Status != "error" || s.Reason != "" || s.FailureID != instance {
		t.Fatalf("retained failure not classified: %+v", s)
	}
	// A lease expiry while Control was down is routing off, not a failure, and
	// a running engine is left for the attach path.
	off := newNativeFixture(t, nativeProber{})
	off.status = service.Status{Stopped: true, Cleanup: "complete", ExitKnown: true}
	off.outcome = host.Outcome{Instance: instance, State: "complete", Reason: "lease-expired"}
	if err := off.remote.classifyRetainedExit(ctx, data); err != nil || off.remote.Snapshot().Status != "off" {
		t.Fatal("lease expiry counted", off.remote.Snapshot(), err)
	}
	// A deliberate stop that completed before Control crashed is off, not a
	// spent failure: resume follows the journaled routing intent instead.
	stopped := newNativeFixture(t, nativeProber{})
	stopped.status = service.Status{Stopped: true, Cleanup: "complete", ExitKnown: true}
	stopped.outcome = host.Outcome{Instance: instance, State: "complete", Reason: "stop"}
	if err := stopped.remote.classifyRetainedExit(ctx, data); err != nil || stopped.remote.Snapshot().Status != "off" || stopped.remote.Snapshot().FailureID != "" {
		t.Fatal("clean retained stop counted", stopped.remote.Snapshot(), err)
	}
	running := newNativeFixture(t, nativeProber{})
	running.status = service.Status{Running: true, PID: 7}
	if err := running.remote.classifyRetainedExit(ctx, data); err != nil || running.remote.Snapshot().Status != "off" || running.remote.instance != "" {
		t.Fatal("a running engine was classified", running.remote.Snapshot(), err)
	}
	if err := running.remote.classifyRetainedExit(ctx, t.TempDir()); err != nil {
		t.Fatal("a folder without a native record must be ignored", err)
	}
}

// The engine's service-initiated stop record is acknowledged on the connection
// that received it, so cleanup does not wait out the delivery timeout.
func TestTerminalRecordIsAcknowledged(t *testing.T) {
	f := newNativeFixture(t, nativeProber{})
	ctx := context.Background()
	rev := testRevision(1)
	f.remote.Restore(&rev)
	if err := f.remote.Start(ctx, rev.Policy); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	cleanup, delivery := f.server.StopWithReason(ctx, "adapter lost", nil)
	if cleanup != nil || delivery != nil {
		t.Fatal("terminal record not acknowledged", cleanup, delivery)
	}
	if elapsed := time.Since(started); elapsed >= protocol.TerminalDeliveryTimeout {
		t.Fatal("acknowledgement only arrived through the delivery timeout", elapsed)
	}
}

func TestNativeExitClassification(t *testing.T) {
	f := newNativeFixture(t, nativeProber{})
	if err := f.remote.Attach(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	instance := f.server.Instance
	complete := service.Status{Stopped: true, Cleanup: "complete", ExitKnown: true, ExitCode: 3}
	f.outcome = host.Outcome{Instance: instance, State: "complete", Reason: "adapter lost"}
	if class, err := f.remote.classifyExit(instance, complete); err != nil || class.reason != ce.ReasonAdapterLost || class.pending {
		t.Fatal("clean exit 3 with completed cleanup is adapter loss", class, err)
	}
	f.outcome = host.Outcome{Instance: instance, State: "failed", Reason: "adapter lost"}
	if class, _ := f.remote.classifyExit(instance, service.Status{Stopped: true, Cleanup: "failed", ExitKnown: true, ExitCode: 1}); class.reason != "" {
		t.Fatal("exit 3 whose cleanup failed must count as a failure", class)
	}
	f.outcome = host.Outcome{Instance: instance, State: "complete", Reason: "failure"}
	if class, _ := f.remote.classifyExit(instance, service.Status{Stopped: true, Cleanup: "complete", ExitKnown: true, ExitCode: 3}); class.reason != "" {
		t.Fatal("exit 3 without the engine's adapter-lost reason must count", class)
	}
	if class, _ := f.remote.classifyExit(instance, service.Status{Stopped: true, Cleanup: "pending"}); !class.pending {
		t.Fatal("pending cleanup must be waited for, never guessed", class)
	}
	f.outcome = host.Outcome{Instance: instance, State: "complete", Reason: "lease-expired"}
	if class, _ := f.remote.classifyExit(instance, service.Status{Stopped: true, Cleanup: "complete", ExitKnown: true}); class.reason != "lease-expired" {
		t.Fatal("lease expiry is routing off, not a failure", class)
	}
	// A deliberate, verified clean stop (exit 0, cleanup complete, reason
	// "stop") is routing off, never a failure.
	f.outcome = host.Outcome{Instance: instance, State: "complete", Reason: "stop"}
	if class, _ := f.remote.classifyExit(instance, service.Status{Stopped: true, Cleanup: "complete", ExitKnown: true}); class.reason != exitStopped {
		t.Fatal("verified clean stop counted as a failure", class)
	}
	// Exit 0 whose cleanup failed, or that carries an error, is not clean.
	f.outcome = host.Outcome{Instance: instance, State: "failed", Reason: "stop", Error: "cleanup failed"}
	if class, _ := f.remote.classifyExit(instance, service.Status{Stopped: true, Cleanup: "failed", ExitKnown: true}); class.reason != "" {
		t.Fatal("stop with failed cleanup was treated as clean", class)
	}
}

func TestNativeAdapterLossReachesTheSnapshotAfterTheServiceStops(t *testing.T) {
	f := newNativeFixture(t, nativeProber{})
	ctx := context.Background()
	rev := testRevision(1)
	f.remote.Restore(&rev)
	if err := f.remote.Start(ctx, rev.Policy); err != nil {
		t.Fatal(err)
	}
	instance := f.server.Instance
	f.status = service.Status{Stopped: true, Cleanup: "complete", ExitKnown: true, ExitCode: 3}
	f.outcome = host.Outcome{Instance: instance, State: "complete", Reason: "adapter lost"}
	f.remote.dial = func(context.Context, localipc.Endpoint) (*localipc.Conn, error) {
		return nil, errors.New("service stopped")
	}
	f.remote.mu.Lock()
	rpc := f.remote.rpc
	f.remote.mu.Unlock()
	f.remote.disconnect(rpc, errors.New("engine connection closed"))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s := f.remote.Snapshot(); s.Status == "error" {
			if s.Reason != ce.ReasonAdapterLost || s.FailureID != instance {
				t.Fatalf("exit classified wrongly: %+v", s)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("snapshot never reported the stopped engine")
}
