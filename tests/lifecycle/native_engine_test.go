package lifecycle_test

import (
	"bufio"
	"context"
	"crypto/sha256"
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
	rpc      *lifecycle.RPC
	instance string
	epoch    uint64
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
	conn, err := localipc.Dial(ctx, localipc.Endpoint{Path: localipc.DefaultPath("engine"), Kind: "engine", Service: service.Engine})
	if err != nil {
		t.Fatal(err)
	}
	c := &nativeClient{rpc: lifecycle.NewRPC(conn)}
	t.Cleanup(func() { c.rpc.Close() })
	var hello struct {
		Instance     string          `json:"engineInstanceId"`
		Status       protocol.Status `json:"status"`
		Capabilities []string        `json:"capabilities"`
	}
	if err := c.rpc.Call(ctx, map[string]any{"method": "hello"}, &hello); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"status", "paged-totals", "terminal-stop"} {
		if !strings.Contains(" "+strings.Join(hello.Capabilities, " ")+" ", " "+required+" ") {
			t.Fatal("wrong engine capabilities", hello.Capabilities)
		}
	}
	c.instance = hello.Instance
	var attached struct {
		Epoch uint64 `json:"epoch"`
	}
	if err := c.call(ctx, "attach", nil, &attached); err != nil || attached.Epoch == 0 {
		t.Fatal(attached, err)
	}
	c.epoch = attached.Epoch
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
	if err := c.call(ctx, method, fields, out); err != nil {
		t.Fatalf("%s: %v", method, err)
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
		if err := service.Uninstall(stop); err != nil {
			t.Error("native uninstall", err)
		}
		for _, name := range []string{"NetSwitchEngine.log", "engine-state.json", "engine-journal.json"} {
			if b, err := os.ReadFile(filepath.Join(data, name)); err == nil {
				t.Logf("NATIVE_EVIDENCE %s: %s", name, b)
			}
		}
	})
	fixture := prepareTUN(t, dir, data)
	if err := service.Start(ctx, service.Engine); err != nil {
		t.Fatal(err)
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
	c, status = attachNative(t, ctx)
	if c.epoch <= old.epoch || c.instance != old.instance || status.Applied == nil || *status.Applied != applied {
		t.Fatal("reattach lost loaded revision", status)
	}
	if old.call(ctx, "renew", nil, nil) == nil {
		t.Fatal("old controller not fenced")
	}
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
	var totals flows.TotalsPage
	nativeMust(t, c, "totals", nil, &totals)
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
	if b, err := exec.CommandContext(ctx, ctl, "cleanup", "--engine", "--data", data).CombinedOutput(); err != nil {
		t.Fatal("installed Ctl cleanup", err, string(b))
	}
	fixture.clean(t)
	t.Run("service-crash-cleanup", func(t *testing.T) {
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
		s, err := service.Query(service.Engine)
		if err != nil || !s.Running {
			t.Fatal(s, err)
		}
		killUnreset(t, s.PID)
		wait(t, "native crash exits service", 15*time.Second, func() bool { s, err := service.Query(service.Engine); return err == nil && s.Stopped })
		// Windows recovery is an SCM command, Linux cleanup is ExecStopPost.
		// Wait for its real object deletion, not just for the process to die.
		waitNativeCleanup(t, fixture)
		end, err := service.Query(service.Engine)
		if err != nil || end.ExitKnown && end.ExitCode == 3 {
			t.Fatal("crash became clean adapter loss", end, err)
		}
		t.Logf("NATIVE_CRASH pid=%d instance=%s final_status=%+v cleanup_complete=true", s.PID, crashed.instance, end)
	})
}

func observeForwardingStall(t *testing.T, c *nativeClient, conn net.Conn, data string, fixture tunFixture) {
	if err := os.WriteFile(filepath.Join(data, "fault-native-forwarding"), []byte("armed"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.WriteFile(filepath.Join(data, "native-forwarding-release"), []byte("release"), 0600) })
	conn.SetDeadline(time.Now().Add(45 * time.Second))
	marker := "native-forward-stalled"
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
		conn.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		n, err := conn.Read(b[:])
		netErr, timedOut := err.(net.Error)
		if n != 0 || !timedOut || !netErr.Timeout() {
			t.Fatal("expected a held, stalled flow, not delivery or disconnect", n, err)
		}
	}
	assertNativeCapture(t, data, fixture)
	t.Logf("M4_STALL kind=forwarding-only observed=%s ipc_replies=%d slowest_ipc_round=%s capture_still_present=true automatic_recovery=false", time.Since(start), responses, slowest)
	if err := os.WriteFile(filepath.Join(data, "native-forwarding-release"), []byte("release"), 0600); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.Contains(line, marker) {
		t.Fatal("release did not resume the held flow", line, err)
	}
	nativeEcho(t, conn, "forwarding-resumed-without-new-instance")
}

func observeWholeServiceStall(t *testing.T, c *nativeClient, fixture tunFixture, ctx context.Context) {
	conn, err := fixture.dial(ctx, "tcp4", fixture.target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	nativeEcho(t, conn, "before-whole-service-stall")
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
	if _, err := fmt.Fprint(conn, "ping whole-service-stalled\n"); err != nil {
		t.Fatal(err)
	}
	for time.Since(start) < 35*time.Second {
		current, err := service.Query(service.Engine)
		if err != nil || !current.Running || current.PID != s.PID {
			t.Fatal("unexpected service transition while suspended", current, err)
		}
		conn.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		n, err := conn.Read(b[:])
		netErr, timedOut := err.(net.Error)
		if n != 0 || !timedOut || !netErr.Timeout() {
			t.Fatal("whole-service stall did not preserve captured blocked traffic", n, err)
		}
	}
	assertNativeCapture(t, "", fixture)
	t.Logf("M4_STALL kind=whole-service observed=%s exceeds_lease=true service_pid=%d ipc_timeout=true automatic_recovery=false", time.Since(start), s.PID)
	resumeNative(t, s.PID)
	resumed = true
	// No queued renewals: on wake the already-lapsed lease must clean up.
	wait(t, "lease expiry after process resumes", 20*time.Second, func() bool { s, err := service.Query(service.Engine); return err == nil && s.Stopped })
	fixture.clean(t)
}
