package lifecycle_test

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/host"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/internal/lifecycle"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/internal/service"
)

type nativeClient struct {
	rpc       *lifecycle.RPC
	instance  string
	epoch     uint64
	stopLease func()
}

func (c *nativeClient) renewUntilStopped(every time.Duration) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	c.stopLease = func() { cancel(); <-done }
	go func() {
		defer close(done)
		tick := time.NewTicker(every)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				probe, stop := context.WithTimeout(ctx, 3*time.Second)
				err := c.call(probe, "renew", nil, nil)
				stop()
				if err != nil {
					return
				}
			}
		}
	}()
}

func (c *nativeClient) call(ctx context.Context, method string, fields map[string]any, out any) error {
	if fields == nil {
		fields = map[string]any{}
	}
	fields["method"], fields["engineInstanceId"], fields["epoch"] = method, c.instance, c.epoch
	return c.rpc.Call(ctx, fields, out)
}

func attachNative(t *testing.T, ctx context.Context) (*nativeClient, protocol.Status) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := localipc.DialNativeEngine(ctx, localipc.Endpoint{Path: localipc.DefaultPath("engine"), Kind: "engine", Service: service.Engine})
	if err != nil {
		t.Fatal("native engine dial", err)
	}
	c := &nativeClient{rpc: lifecycle.NewRPC(conn)}
	t.Cleanup(func() { c.rpc.Close() })
	var hello struct {
		Instance     string          `json:"engineInstanceId"`
		Status       protocol.Status `json:"status"`
		Capabilities []string        `json:"capabilities"`
	}
	if err := c.rpc.Call(ctx, map[string]any{"method": "hello"}, &hello); err != nil {
		t.Fatal("native engine hello", err)
	}
	for _, required := range []string{"status", "paged-totals", "totals-ack", "terminal-stop"} {
		if !strings.Contains(" "+strings.Join(hello.Capabilities, " ")+" ", " "+required+" ") {
			t.Fatal("wrong engine capabilities", hello.Capabilities)
		}
	}
	c.instance = hello.Instance
	var attached struct {
		Epoch uint64 `json:"epoch"`
	}
	if err := c.call(ctx, "attach", nil, &attached); err != nil || attached.Epoch == 0 {
		t.Fatal("native engine attach", attached, err)
	}
	c.epoch = attached.Epoch
	c.renewUntilStopped(5 * time.Second)
	t.Cleanup(c.stopLease)
	state, err := service.Query(service.Engine)
	if err != nil || !state.Running || state.PID != uint32(hello.Status.PID) {
		t.Fatal("protocol is not the installed SCM/systemd process", state, hello.Status, err)
	}
	image := nativeImage(t, state.PID)
	expected := filepath.Join(os.Getenv("NETSWITCH_LIFECYCLE_DIR"), binary("netswitch-engine"))
	if !strings.EqualFold(filepath.Clean(image), filepath.Clean(expected)) {
		t.Fatal("wrong running native image", image, expected)
	}
	t.Logf("NATIVE_SERVICE instance=%s epoch=%d service_pid=%d protocol_pid=%d image=%s", c.instance, c.epoch, state.PID, hello.Status.PID, image)
	return c, hello.Status
}

func nativeMust(t *testing.T, c *nativeClient, method string, fields map[string]any, out any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if method == "stop" && c.stopLease != nil {
		c.stopLease()
	}
	if err := c.call(ctx, method, fields, out); err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	if method == "stop" {
		c.rpc.Close()
	}
}

func nativeEcho(t *testing.T, conn net.Conn, marker string) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(conn, "ping %s\n", marker); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.Contains(line, marker) {
		t.Fatalf("echo %q: %q %v", marker, line, err)
	}
}

func readNativeTotals(t *testing.T, c *nativeClient, between func()) flows.TotalsPage {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := flows.TotalsPage{Apps: map[string]flows.Counter{}, Lines: map[string]flows.Counter{}, Count: -1}
	cursor := ""
	seen := map[string]bool{}
	pages := 0
	start := time.Now()
	for {
		var page flows.TotalsPage
		if err := c.call(ctx, "totals", map[string]any{"cursor": cursor}, &page); err != nil {
			t.Fatal("full native totals read", err)
		}
		if page.Instance != c.instance {
			t.Fatal("totals crossed an engine restart")
		}
		if result.Count < 0 {
			result.Count, result.Receipt = page.Count, page.Receipt
		}
		if result.Receipt == "" || page.Count != result.Count || page.Receipt != result.Receipt {
			t.Fatal("native totals snapshot changed")
		}
		for id, n := range page.Apps {
			if _, ok := result.Apps[id]; ok {
				t.Fatal("duplicate app total")
			}
			result.Apps[id] = n
		}
		for id, n := range page.Lines {
			if _, ok := result.Lines[id]; ok {
				t.Fatal("duplicate line total")
			}
			result.Lines[id] = n
		}
		pages++
		if page.Cursor == "" {
			break
		}
		if seen[page.Cursor] || len(page.Apps)+len(page.Lines) == 0 {
			t.Fatal("native totals made no progress")
		}
		seen[page.Cursor] = true
		cursor = page.Cursor
		if between != nil && pages%8 == 0 {
			between()
		}
	}
	if len(result.Apps)+len(result.Lines) != result.Count {
		t.Fatal("native totals incomplete")
	}
	if time.Since(start) >= 10*time.Second {
		t.Fatal("full native totals read exceeded snapshot lifetime")
	}
	t.Logf("NATIVE_TOTALS apps=%d lines=%d pages=%d elapsed=%s snapshot_lifetime=10s final_cursor=empty", len(result.Apps), len(result.Lines), pages, time.Since(start))
	nativeMust(t, c, "ackTotals", map[string]any{"receipt": result.Receipt, "opId": "ack-" + result.Receipt}, nil)
	return result
}

func observeNativeCounters(t *testing.T, c *nativeClient, phase string) {
	t.Helper()
	var reply struct {
		Engine map[string]json.RawMessage `json:"engine"`
	}
	nativeMust(t, c, "stats", nil, &reply)
	selected := map[string]json.RawMessage{}
	for _, key := range []string{"flows", "wintun", "tunKernel", "tcpSegmentsSent", "tcpRetransmits", "tcpDialFailed", "tunDropped", "tunQueued", "transportDropped"} {
		if value := reply.Engine[key]; len(value) > 0 {
			selected[key] = value
		}
	}
	b, err := json.Marshal(selected)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("M4_PROGRESS phase=%s instance=%s counters=%s", phase, c.instance, b)
}

// Native services are qualified separately from the still-active M2 adapter.
// Both builds use Ctl install, the real service manager and production IPC ACLs.
func TestNativeEngineService(t *testing.T) {
	if !hosted() || os.Getenv("NETSWITCH_NATIVE_CI") != "1" {
		t.Skip("native service proof is hosted-only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	dir := os.Getenv("NETSWITCH_LIFECYCLE_DIR")
	if !filepath.IsAbs(dir) {
		t.Fatal("missing native installation directory")
	}
	faults := os.Getenv("NETSWITCH_NATIVE_FAULTS") == "1"
	data := testData() + "-native"
	if faults {
		data += "-faults"
	}
	ctl := filepath.Join(dir, binary("netswitchctl"))
	for _, name := range []string{"netswitch", "netswitch-engine", "netswitchctl", "netswitch-desktop"} {
		path := filepath.Join(dir, binary(name))
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		flag := "version"
		if name == "netswitch" || name == "netswitch-desktop" {
			flag = "--version"
		}
		version, err := exec.CommandContext(ctx, path, flag).CombinedOutput()
		if err != nil {
			t.Fatal(err, string(version))
		}
		t.Logf("NATIVE_BINARY path=%s sha256=%x version=%s faults=%t", path, sha256.Sum256(b), strings.TrimSpace(string(version)), faults)
	}
	if b, err := exec.CommandContext(ctx, ctl, "install", "--directory", dir, "--data", data, "--mode", "tun").CombinedOutput(); err != nil {
		t.Fatal("native install without adapter", err, string(b))
	}
	t.Cleanup(func() {
		stop, done := context.WithTimeout(context.Background(), 45*time.Second)
		defer done()
		if err := service.Stop(stop, service.Engine); err != nil {
			t.Log("native cleanup stop", err)
			force, finish := context.WithTimeout(context.Background(), 15*time.Second)
			if err := service.ForceStop(force, service.Engine); err != nil {
				t.Log("native cleanup force stop", err)
			}
			finish()
		}
		if err := service.Uninstall(stop); err != nil {
			t.Error("native uninstall", err)
		}
		for _, name := range []string{"NetSwitchEngine.log", "engine-state.json", "engine-journal.json", "native-startup-phase.txt", "native-startup-stacks.txt"} {
			if b, err := os.ReadFile(filepath.Join(data, name)); err == nil {
				t.Logf("NATIVE_EVIDENCE %s: %s", name, b)
			}
		}
		if record, err := host.ReadRecord(filepath.Join(data, "engine-state.json")); err == nil {
			outcome, err := host.ReadOutcome(data, record.Instance)
			t.Logf("NATIVE_EVIDENCE cleanup: %+v read_error=%v", outcome, err)
		}
	})
	fixture := prepareTUN(t, dir, data)
	startCtx, startCancel := context.WithTimeout(ctx, 45*time.Second)
	startErr := service.Start(startCtx, service.Engine)
	startCancel()
	if startErr != nil {
		status, queryErr := service.Query(service.Engine)
		t.Logf("native start failed: %v status=%+v query=%v", startErr, status, queryErr)
		killCtx, killCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer killCancel()
		if err := service.ForceStop(killCtx, service.Engine); err != nil {
			t.Log("failed startup termination", err)
		}
		t.Fatal(startErr)
	}
	c, initial := attachNative(t, ctx)
	if initial.State != "off" || initial.Applied != nil {
		t.Fatal("new instance has loaded history", initial)
	}
	t.Run("installed-native-engine-denies-other-user", func(t *testing.T) {
		other := newActor(t, "NSNativeOther")
		t.Cleanup(other.close)
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		if b, err := other.command(self, "client", "engine-denied").CombinedOutput(); err != nil {
			t.Fatal("native service ACL", err, string(b))
		}
	})
	config := policy.Config{Lines: []platform.Line{{ID: "a1", Interface: fixture.line}}}
	rev := policy.Revision{N: 1, Config: config, Hash: policy.Hash(config)}
	var started policy.Applied
	nativeMust(t, c, "start", map[string]any{"revision": rev}, &started)
	var status protocol.Status
	nativeMust(t, c, "status", nil, &status)
	if status.State != "on" || status.Applied == nil || *status.Applied != started || status.Started.IsZero() {
		t.Fatal("start not loaded", status, started)
	}
	conn, err := fixture.dial(ctx, "tcp4", fixture.target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	nativeEcho(t, conn, "native-before-apply")
	var full flows.Page
	nativeMust(t, c, "flows", map[string]any{"all": true}, &full)
	destination := netip.MustParseAddrPort(fixture.target)
	captured := false
	for _, f := range full.Flows {
		captured = captured || f.Destination == destination && f.Line == "a1"
	}
	if !captured || full.Counted == nil {
		t.Fatal("precondition: traffic was not in the real native TUN", full)
	}
	assertNativeCapture(t, data, fixture)
	rev.N = 2
	var applied, repeated policy.Applied
	nativeMust(t, c, "apply", map[string]any{"revision": rev}, &applied)
	nativeMust(t, c, "apply", map[string]any{"revision": rev}, &repeated)
	if applied != repeated || applied.Point <= started.Point {
		t.Fatal("apply point was not stable/ordered", applied, repeated)
	}
	nativeEcho(t, conn, "native-after-apply")
	bad := rev
	bad.Config.IPv6 = true
	bad.Hash = policy.Hash(bad.Config)
	if err := c.call(ctx, "apply", map[string]any{"revision": bad}, nil); err == nil {
		t.Fatal("same-number conflicting policy accepted")
	}
	bad = rev
	bad.N = 1
	if err := c.call(ctx, "apply", map[string]any{"revision": bad}, nil); err == nil {
		t.Fatal("stale revision accepted")
	}
	old := c
	old.stopLease()
	c, status = attachNative(t, ctx)
	if c.epoch <= old.epoch || c.instance != old.instance || status.Applied == nil || *status.Applied != applied {
		t.Fatal("reattach lost loaded revision", status)
	}
	if old.call(ctx, "renew", nil, nil) == nil {
		t.Fatal("old controller not fenced")
	}
	old.rpc.Close()
	nativeEcho(t, conn, "native-after-reattach")
	newer, err := fixture.dial(ctx, "tcp4", fixture.target)
	if err != nil {
		t.Fatal(err)
	}
	defer newer.Close()
	nativeEcho(t, newer, "newer-than-cutoff")
	var closed flows.CloseResult
	closure := map[string]any{"opId": "native-cutoff", "selector": flows.Selector{Line: "a1"}, "startedBefore": applied.Point}
	nativeMust(t, c, "closeFlows", closure, &closed)
	if closed.Closed < 1 || closed.Failed != 0 {
		t.Fatal("old flow not selected", closed)
	}
	expectClosed(t, conn)
	var replay flows.CloseResult
	nativeMust(t, c, "closeFlows", closure, &replay)
	if replay != closed {
		t.Fatal("closure retry changed result", replay, closed)
	}
	nativeEcho(t, newer, "newer-survived-closure-retry")
	totals := readNativeTotals(t, c, nil)
	if totals.Lines["a1"].Up == 0 || totals.Lines["a1"].Down == 0 {
		t.Fatal("closed-flow accounting missing", totals)
	}
	if !faults {
		t.Run("product-build-ignores-forwarding-fault", func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(data, "fault-native-forwarding"), []byte("armed"), 0600); err != nil {
				t.Fatal(err)
			}
			nativeEcho(t, newer, "product-has-no-test-interposer")
			if _, err := os.Stat(filepath.Join(data, "native-forwarding-hit.json")); !os.IsNotExist(err) {
				t.Fatal("product enabled test fault", err)
			}
		})
	} else {
		t.Run("read-deadline-control-with-forwarding-live", func(t *testing.T) {
			sample := nativeSocketObserver(t, newer)
			quiet := &stalledTraffic{conn: newer, sent: time.Now(), sample: sample}
			for time.Since(quiet.sent) < 35*time.Second {
				quiet.poll(t)
			}
			sample("read-deadline-control-end")
			t.Logf("M4_DEADLINE_CONTROL observed=%s poll_deadlines=%d flow=%s forwarding=live", time.Since(quiet.sent), quiet.polls, quiet.outcome())
			nativeEcho(t, newer, "same-stream-after-deadline-control")
		})
		t.Run("totals-capacity-over-installed-transport", func(t *testing.T) {
			var gauges flows.Gauges
			nativeMust(t, c, "testFault", map[string]any{"fault": map[string]any{"kind": "totals-capacity"}}, &gauges)
			if gauges.AccountingApps != flows.AccountingEntries || gauges.AccountingLines != flows.AccountingEntries {
				t.Fatal("capacity fixture did not fill retained identities", gauges)
			}
			result := readNativeTotals(t, c, func() { nativeEcho(t, newer, "held-flow-during-full-totals-read") })
			if len(result.Apps) != flows.AccountingEntries || len(result.Lines) != flows.AccountingEntries {
				t.Fatal("full transport read lost accounting")
			}
		})
		t.Run("forwarding-only-stall-observation", func(t *testing.T) { observeForwardingStall(t, c, newer, data, fixture) })
	}
	nativeMust(t, c, "stop", nil, nil)
	if err := service.WaitStopped(ctx, service.Engine); err != nil {
		t.Fatal(err)
	}
	fixture.clean(t)
	end, err := service.Query(service.Engine)
	if err != nil || !end.ExitKnown || end.ExitCode != 0 {
		t.Fatal("clean service exit not retained", end, err)
	}
	var history host.Record
	if err := lifecycle.Read(filepath.Join(data, "engine-state.json"), &history); err != nil || history.Epoch != c.epoch || history.N != rev.N {
		t.Fatal("durable service state", history, err)
	}
	if err := service.Start(ctx, service.Engine); err != nil {
		t.Fatal(err)
	}
	previous := c
	c, initial = attachNative(t, ctx)
	if c.instance == previous.instance || c.epoch <= previous.epoch || initial.Applied != nil || initial.State != "off" {
		t.Fatal("restart confused history with loaded state", initial, c.epoch)
	}
	if err := c.rpc.Call(ctx, map[string]any{"method": "closeFlows", "engineInstanceId": previous.instance, "epoch": previous.epoch, "opId": "native-cutoff", "selector": flows.Selector{Line: "a1"}}, nil); err == nil {
		t.Fatal("old-instance closure accepted")
	}
	nativeMust(t, c, "start", map[string]any{"revision": rev}, &started)
	if faults {
		t.Run("whole-service-stall-observation", func(t *testing.T) { observeWholeServiceStall(t, c, fixture, ctx) })
	} else {
		nativeMust(t, c, "stop", nil, nil)
	}
	if err := service.WaitStopped(ctx, service.Engine); err != nil {
		t.Fatal(err)
	}
	fixture.clean(t)
	direct, err := fixture.dial(ctx, "tcp4", fixture.target)
	if err != nil {
		t.Fatal("direct traffic after native cleanup", err)
	}
	defer direct.Close()
	nativeEcho(t, direct, "native-cleanup-restored-direct-traffic")
	for _, automatic := range []bool{true, false} {
		name := "service-crash-cleanup"
		if !automatic {
			name = "explicit-ctl-removes-real-leftovers"
		}
		t.Run(name, func(t *testing.T) {
			if !automatic {
				restore := pauseNativeRecovery(t)
				defer restore()
			}
			if err := service.Start(ctx, service.Engine); err != nil {
				t.Fatal(err)
			}
			crashed, _ := attachNative(t, ctx)
			nativeMust(t, crashed, "start", map[string]any{"revision": rev}, nil)
			held, err := fixture.dial(ctx, "tcp4", fixture.target)
			if err != nil {
				t.Fatal(err)
			}
			defer held.Close()
			nativeEcho(t, held, "capture-before-service-crash")
			assertNativeCapture(t, data, fixture)
			assertNativeOwnedLeftovers(t, data, crashed.instance)
			s, err := service.Query(service.Engine)
			if err != nil || !s.Running {
				t.Fatal(s, err)
			}
			killUnreset(t, s.PID)
			crashed.stopLease()
			wait(t, "native crash exits service", 15*time.Second, func() bool { s, err := service.Query(service.Engine); return err == nil && s.Stopped })
			// Windows recovery is an SCM command, Linux cleanup is ExecStopPost.
			// Wait for its real object deletion, not just for the process to die.
			if !automatic {
				assertNativeOwnedLeftovers(t, data, crashed.instance)
				if b, err := runNativeCleanup(ctx, ctl, data).CombinedOutput(); err != nil {
					t.Fatal("explicit native cleanup", err, string(b))
				}
			}
			waitNativeCleanup(t, fixture, data, crashed.instance)
			var end service.Status
			wait(t, "native crash recovery result", 10*time.Second, func() bool {
				var err error
				end, err = service.Query(service.Engine)
				return err == nil && (end.Cleanup == "complete" || end.Cleanup == "failed")
			})
			if end.Cleanup != "complete" || end.ExitKnown && (end.ExitCode == 3 || end.ExitCode == 0) || end.MainExitKnown && (end.MainExitCode == 3 || end.MainExitCode == 0) {
				t.Fatal("crash became a clean exit or adapter loss", end)
			}
			t.Logf("NATIVE_CRASH pid=%d instance=%s final_status=%+v cleanup_complete=true", s.PID, crashed.instance, end)
		})
	}
	if faults {
		for _, failCleanup := range []bool{false, true} {
			t.Run(fmt.Sprintf("service-outcome-three-cleanup-fails-%t", failCleanup), func(t *testing.T) {
				if err := os.WriteFile(filepath.Join(data, "fault-native-exit3"), []byte("armed"), 0600); err != nil {
					t.Fatal(err)
				}
				defer os.Remove(filepath.Join(data, "fault-native-exit3"))
				if failCleanup {
					if err := os.WriteFile(filepath.Join(data, "fault-native-recovery"), []byte("armed"), 0600); err != nil {
						t.Fatal(err)
					}
					defer os.Remove(filepath.Join(data, "fault-native-recovery"))
				}
				if err := service.Start(ctx, service.Engine); err != nil {
					t.Fatal(err)
				}
				outcome, _ := attachNative(t, ctx)
				nativeMust(t, outcome, "start", map[string]any{"revision": rev}, nil)
				nativeMust(t, outcome, "stop", nil, nil)
				var end service.Status
				wait(t, "real manager and recovery outcome", 30*time.Second, func() bool {
					var err error
					end, err = service.Query(service.Engine)
					return err == nil && end.Stopped && (end.Cleanup == "complete" || end.Cleanup == "failed")
				})
				if !end.MainExitKnown || end.MainExitCode != 3 || !end.ExitKnown {
					t.Fatal("service manager lost native exit 3", end)
				}
				if failCleanup {
					if end.ExitCode != 1 || end.Cleanup != "failed" || !strings.Contains(end.LastError, "hosted recovery failure") {
						t.Fatal("failed cleanup was reported clean", end)
					}
				} else if end.ExitCode != 3 || end.Cleanup != "complete" {
					t.Fatal("clean outcome did not survive real service manager", end)
				}
				t.Logf("NATIVE_MANAGER_OUTCOME %+v", end)
			})
		}
	}
}

func observeForwardingStall(t *testing.T, c *nativeClient, conn net.Conn, data string, fixture tunFixture) {
	observeNativeCounters(t, c, "before-read-pump-stall")
	sample := nativeSocketObserver(t, conn)
	sample("before-read-pump-stall")
	if err := os.WriteFile(filepath.Join(data, "fault-native-forwarding"), []byte("armed"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.WriteFile(filepath.Join(data, "native-forwarding-release"), []byte("release"), 0600) })
	if err := conn.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	marker := "native-forward-stalled"
	traffic := &stalledTraffic{conn: conn, sent: time.Now(), sample: sample}
	if _, err := fmt.Fprintf(conn, "ping %s\n", marker); err != nil {
		t.Fatal(err)
	}
	var hit struct {
		PID   int `json:"pid"`
		Bytes int `json:"bytes"`
	}
	wait(t, "native read pump reached stall", 5*time.Second, func() bool { return lifecycle.Read(filepath.Join(data, "native-forwarding-hit.json"), &hit) == nil })
	state, err := service.Query(service.Engine)
	if err != nil || hit.PID != int(state.PID) || hit.Bytes <= 0 {
		t.Fatal("stall precondition", hit, state, err)
	}
	start := time.Now()
	responses := 0
	var slowest time.Duration
	nextSample := start.Add(5 * time.Second)
	for time.Since(start) < 22*time.Second {
		probeStart := time.Now()
		probe, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		var version string
		err := c.call(probe, "renew", nil, nil)
		if err == nil {
			err = c.call(probe, "version", nil, &version)
		}
		cancel()
		if err != nil {
			t.Fatal("control path stalled with forwarding", err)
		}
		slowest = max(slowest, time.Since(probeStart))
		responses++
		traffic.poll(t)
		if !time.Now().Before(nextSample) {
			sample("during-read-pump-stall")
			nextSample = time.Now().Add(5 * time.Second)
		}
	}
	assertNativeCapture(t, data, fixture)
	observeNativeCounters(t, c, "during-read-pump-stall")
	sample("before-read-pump-release")
	t.Logf("M4_STALL kind=forwarding-only observed=%s since_send=%s ipc_replies=%d slowest_ipc_round=%s flow=%s poll_deadlines=%d capture_still_present=true automatic_recovery=false", time.Since(start), time.Since(traffic.sent), responses, slowest, traffic.outcome(), traffic.polls)
	if err := os.WriteFile(filepath.Join(data, "native-forwarding-release"), []byte("release"), 0600); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	sample("after-read-pump-release")
	t.Logf("M4_FLOW phase=after-read-pump-release same_stream_resumed=%t reply=%q error=%v", err == nil && strings.Contains(line, marker), line, err)
	if err != nil || !strings.Contains(line, marker) {
		t.Error("release did not resume the held flow", line, err)
	} else {
		nativeEcho(t, conn, "forwarding-resumed-without-new-instance")
	}
	observeNativeCounters(t, c, "after-read-pump-stall")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fresh, err := fixture.dial(ctx, "tcp4", fixture.target)
	if err != nil {
		t.Fatal("fresh connection after read pump release", err)
	}
	defer fresh.Close()
	nativeEcho(t, fresh, "fresh-connection-after-read-pump-release")
	t.Log("M4_FLOW phase=after-read-pump-release fresh_connection=passed (does not substitute for the original stream)")
}

func observeWholeServiceStall(t *testing.T, c *nativeClient, fixture tunFixture, ctx context.Context) {
	conn, err := fixture.dial(ctx, "tcp4", fixture.target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	nativeEcho(t, conn, "before-whole-service-stall")
	observeNativeCounters(t, c, "before-whole-service-stall")
	sample := nativeSocketObserver(t, conn)
	sample("before-whole-service-stall")
	if err := conn.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	c.stopLease()
	nativeMust(t, c, "renew", nil, nil)
	s, err := service.Query(service.Engine)
	if err != nil || !s.Running {
		t.Fatal(s, err)
	}
	suspendAdapter(t, s.PID)
	resumed := false
	defer func() {
		if !resumed {
			resumeNative(t, s.PID)
		}
	}()
	start := time.Now()
	probe, stopProbe := context.WithTimeout(ctx, 2*time.Second)
	err = c.call(probe, "version", nil, nil)
	stopProbe()
	if err == nil {
		t.Fatal("whole-service suspension left IPC responsive")
	}
	t.Log("M4_PROGRESS phase=whole-service-stall counters=unavailable (service suspended)")
	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	traffic := &stalledTraffic{conn: conn, sent: time.Now(), sample: sample}
	if _, err := fmt.Fprint(conn, "ping whole-service-stalled\n"); err != nil {
		t.Fatal(err)
	}
	nextSample := time.Now().Add(5 * time.Second)
	for time.Since(start) < 35*time.Second {
		current, err := service.Query(service.Engine)
		if err != nil || !current.Running || current.PID != s.PID {
			t.Fatal("unexpected service transition while suspended", current, err)
		}
		traffic.poll(t)
		if !time.Now().Before(nextSample) {
			sample("during-whole-service-stall")
			nextSample = time.Now().Add(5 * time.Second)
		}
	}
	assertNativeCapture(t, "", fixture)
	sample("before-whole-service-resume")
	t.Logf("M4_STALL kind=whole-service observed=%s since_send=%s exceeds_lease=true service_pid=%d ipc_timeout=true flow=%s poll_deadlines=%d automatic_recovery=false", time.Since(start), time.Since(traffic.sent), s.PID, traffic.outcome(), traffic.polls)
	resumeNative(t, s.PID)
	resumed = true
	// No queued renewals: on wake the already-lapsed lease must clean up.
	wait(t, "lease expiry after process resumes", 20*time.Second, func() bool { s, err := service.Query(service.Engine); return err == nil && s.Stopped })
	fixture.clean(t)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	n, err := conn.Read(b[:])
	sample("after-whole-service-lease-cleanup")
	t.Logf("M4_FLOW phase=after-whole-service-lease-cleanup read=%s bytes=%d error=%v", stallReadKind(n, err), n, err)
}
