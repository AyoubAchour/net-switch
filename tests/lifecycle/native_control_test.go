package lifecycle_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/host"
	"github.com/AyoubAchour/net-switch/internal/lifecycle"
	"github.com/AyoubAchour/net-switch/internal/lines"
	"github.com/AyoubAchour/net-switch/internal/service"
	"github.com/AyoubAchour/net-switch/internal/usage"
)

// controlJournal is the part of Control's journal these proofs read.
type controlJournal struct {
	Wanted   bool    `json:"wanted"`
	Failures []int64 `json:"failures"`
	Losses   []int64 `json:"adapterLosses"`
	Instance string  `json:"engineInstanceId"`
}

func readControlJournal(t *testing.T, data string) controlJournal {
	t.Helper()
	var j controlJournal
	if err := lifecycle.Read(filepath.Join(data, "control-journal.json"), &j); err != nil {
		t.Fatal("control journal", err)
	}
	return j
}

// routedApps reads the per-app entries of Control's durable routed-usage
// record. The runner's own background traffic crosses the TUN too, so the
// exactness checks follow one identity: this test process, found by the first
// echo whose bytes appear exactly once.
func routedApps(t *testing.T, data string) map[string]usage.RoutedEntry {
	t.Helper()
	out := map[string]usage.RoutedEntry{}
	b, err := os.ReadFile(filepath.Join(data, "usage.json"))
	if os.IsNotExist(err) {
		return out
	}
	if err != nil {
		t.Fatal(err)
	}
	routed := usage.LoadRouted(b)
	if routed == nil {
		return out
	}
	for id, e := range routed.Apps {
		out[id] = *e
	}
	return out
}

// findOwnIdentity echoes n bytes and returns the one app identity whose totals
// grew by exactly n up and n down. Two candidates would mean the probe is
// ambiguous, which fails rather than guessing.
func findOwnIdentity(t *testing.T, ctx context.Context, fixture tunFixture, data string, n uint64) (string, usage.RoutedEntry) {
	t.Helper()
	before := routedApps(t, data)
	echoExact(t, ctx, fixture, int(n))
	var key string
	var entry usage.RoutedEntry
	wait(t, "own app identity appears in routed usage", 25*time.Second, func() bool {
		matches := 0
		for id, e := range routedApps(t, data) {
			b := before[id]
			if e.Up == b.Up+n && e.Down == b.Down+n {
				matches++
				key, entry = id, e
			}
		}
		return matches == 1
	})
	return key, entry
}

// echoExact sends exactly n bytes through the TUN and reads them back, so the
// engine's accounting for this flow is n up and n down.
func echoExact(t *testing.T, ctx context.Context, fixture tunFixture, n int) {
	t.Helper()
	conn, err := fixture.dial(ctx, "tcp4", fixture.target)
	if err != nil {
		t.Fatal("TUN dial", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	payload := make([]byte, n)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := conn.Write(payload); done <- err }()
	reply := make([]byte, n)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal("echo read", err)
	}
	if err := <-done; err != nil {
		t.Fatal("echo write", err)
	}
	for i := range payload {
		if payload[i] != reply[i] {
			t.Fatal("echo corrupted")
		}
	}
}

func waitRouting(t *testing.T, c *client, label string, bound time.Duration, accept func(status) bool) status {
	t.Helper()
	var s status
	wait(t, label, bound, func() bool { s = getStatus(t, c); return accept(s) })
	return s
}

func nativeChildPID(t *testing.T, data, instance string) uint32 {
	t.Helper()
	out, err := host.ReadOutcome(data, instance)
	if err != nil || out.Child == nil || out.Child.PID == 0 {
		t.Fatal("instance has no verified child", out, err)
	}
	return out.Child.PID
}

// TestNativeControlCutover drives the installed native engine through the
// installed Control: sign-in, routing, exact accounting across Control crashes,
// restart budget, adapter-loss classification and the 70 s recovery bound. It
// needs the fault build: hosted actors have no desktop session, so their
// presence is injected, and the crash barriers only exist there.
func TestNativeControlCutover(t *testing.T) {
	if !hosted() || os.Getenv("NETSWITCH_NATIVE_CI") != "1" {
		t.Skip("native Control proof is hosted-only")
	}
	if os.Getenv("NETSWITCH_NATIVE_FAULTS") != "1" {
		t.Skip("native Control proof needs the fault build's barriers and session fixture")
	}
	if !lifecycle.Administrator() {
		t.Fatal("lifecycle harness must be elevated")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	dir := os.Getenv("NETSWITCH_LIFECYCLE_DIR")
	if !filepath.IsAbs(dir) {
		t.Fatal("missing native installation directory")
	}
	data := testData() + "-control"
	if err := lifecycle.PrepareDirectory(data); err != nil {
		t.Fatal(err)
	}
	ctl := filepath.Join(dir, binary("netswitchctl"))
	owner := newActor(t, "NSNativeControlOwner")
	// Hosted actors have no desktop session on either OS; the fault build's
	// fixture injects their presence. IPC identity still uses real OS tokens.
	if err := lifecycle.Save(filepath.Join(data, "fault-owner-sessions.json"), map[string]bool{owner.id(): true}); err != nil {
		t.Fatal(err)
	}
	if b, err := exec.CommandContext(ctx, ctl, "install", "--directory", dir, "--data", data, "--mode", "tun").CombinedOutput(); err != nil {
		t.Fatal("native install", err, string(b))
	}
	t.Cleanup(func() {
		stop, done := context.WithTimeout(context.Background(), 60*time.Second)
		defer done()
		if err := service.Uninstall(stop); err != nil {
			t.Error("native uninstall", err)
		}
		for _, name := range []string{"NetSwitch.log", "NetSwitchEngine.log", "control-journal.json", "usage.json"} {
			if b, err := os.ReadFile(filepath.Join(data, name)); err == nil {
				t.Logf("NATIVE_CONTROL_EVIDENCE %s: %s", name, b)
			}
		}
	})
	fixture := prepareTUN(t, dir, data)
	if err := lifecycle.Save(filepath.Join(data, "settings.json"), map[string]any{"lines": []lines.Line{{ID: "a1", Alias: fixture.line, Label: "Native line", Weight: 1}}, "ipv6": "off", "checkForUpdates": false}); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.Enroll(ctx, data, owner.id()); err != nil {
		t.Fatal(err)
	}
	if err := service.SetOwner(owner.id()); err != nil {
		t.Fatal(err)
	}
	if err := service.Start(ctx, service.Control); err != nil {
		t.Fatal(err)
	}
	c := openClient(t, owner, false)
	c.must(t, "signin", nil, nil)
	first := waitRouting(t, c, "native routing on through the installed Control", 60*time.Second, func(s status) bool { return s.Routing == "on" && s.Instance != "" })
	t.Logf("NATIVE_CONTROL routing=on instance=%s control_pid=%d", first.Instance, first.ControlPID)
	if runtime.GOOS == "linux" {
		time.Sleep(time.Second) // the namespace relay follows the TUN's route change
	}
	t.Run("routes-traffic-through-the-native-engine", func(t *testing.T) {
		echoExact(t, ctx, fixture, 4096)
		assertNativeCapture(t, first.Instance, fixture)
		j := readControlJournal(t, data)
		if !j.Wanted || j.Instance != first.Instance || len(j.Failures) != 0 {
			t.Fatalf("journal after sign-in: %+v", j)
		}
	})
	t.Run("engine-service-is-never-restarted-by-the-manager", func(t *testing.T) {
		assertEngineHasNoManagerRestart(t)
	})
	t.Run("exact-usage-survives-control-crashes-around-the-ack", func(t *testing.T) {
		const n = 65536
		key, start := findOwnIdentity(t, ctx, fixture, data, n)
		t.Logf("NATIVE_CONTROL_USAGE_IDENTITY app=%q up=%d down=%d", key, start.Up, start.Down)
		own := func() usage.RoutedEntry { return routedApps(t, data)[key] }
		settle := func(label string, wantUp, wantDown uint64) {
			wait(t, label, 25*time.Second, func() bool { e := own(); return e.Up == wantUp && e.Down == wantDown })
		}
		base := start
		// Crash between the durable usage commit and the acknowledgement.
		arm(t, data, "control-after-usage-commit")
		echoExact(t, ctx, fixture, n)
		pid := barrier(t, data, "control-after-usage-commit")
		if e := own(); e.Up != base.Up+n || e.Down != base.Down+n {
			t.Fatalf("usage not committed before the acknowledgement: %+v want up=%d down=%d", e, base.Up+n, base.Down+n)
		}
		kill(t, pid)
		wait(t, "Control restarts after the commit crash", 30*time.Second, func() bool { s, err := service.Query(service.Control); return err == nil && s.Running && s.PID != pid })
		c = openClient(t, owner, false)
		after := waitRouting(t, c, "reattach after the commit crash", 20*time.Second, func(s status) bool { return s.Routing == "on" })
		if after.Instance != first.Instance {
			t.Fatal("a Control crash replaced the engine instance", after.Instance, first.Instance)
		}
		// The re-read sees the same unretired counters: no double count.
		settle("totals unchanged after re-read", base.Up+n, base.Down+n)
		time.Sleep(12 * time.Second) // two accounting rounds without any traffic
		if e := own(); e.Up != base.Up+n || e.Down != base.Down+n {
			t.Fatalf("bytes double counted after the commit/ack crash: %+v want up=%d down=%d", e, base.Up+n, base.Down+n)
		}
		// Crash right after the acknowledgement, before the next read.
		arm(t, data, "control-after-totals-ack")
		echoExact(t, ctx, fixture, n)
		pid = barrier(t, data, "control-after-totals-ack")
		kill(t, pid)
		wait(t, "Control restarts after the ack crash", 30*time.Second, func() bool { s, err := service.Query(service.Control); return err == nil && s.Running && s.PID != pid })
		c = openClient(t, owner, false)
		waitRouting(t, c, "reattach after the ack crash", 20*time.Second, func(s status) bool { return s.Routing == "on" && s.Instance == first.Instance })
		echoExact(t, ctx, fixture, n)
		settle("totals exact after the ack crash", base.Up+3*n, base.Down+3*n)
		e := own()
		t.Logf("NATIVE_CONTROL_USAGE app=%q base_up=%d base_down=%d up=%d down=%d apps=%d exact=true", key, base.Up, base.Down, e.Up, e.Down, len(routedApps(t, data)))
	})
	t.Run("child-crash-counts-one-failure-and-restarts", func(t *testing.T) {
		before := getStatus(t, c)
		child := nativeChildPID(t, data, before.Instance)
		gone, _, _ := pinNativeChild(t, child)
		recovery := newNativeRecoveryTimer()
		killUnreset(t, child)
		wait(t, "child death", 5*time.Second, gone)
		after := waitRouting(t, c, "Control restarts a crashed engine", 45*time.Second, func(s status) bool { return s.Routing == "on" && s.Instance != "" && s.Instance != before.Instance })
		j := readControlJournal(t, data)
		if len(j.Failures) != 1 || len(j.Losses) != 0 {
			t.Fatalf("one crash must use exactly one failure: %+v", j)
		}
		t.Logf("NATIVE_CONTROL_CRASH old=%s new=%s restarted_after=%s failures=%d", before.Instance, after.Instance, recovery.elapsed(), len(j.Failures))
		echoExact(t, ctx, fixture, 1024)
	})
	t.Run("adapter-loss-restarts-free-then-counts", func(t *testing.T) {
		failuresBefore := len(readControlJournal(t, data).Failures)
		for loss := 1; loss <= 4; loss++ {
			before := getStatus(t, c)
			if err := os.WriteFile(filepath.Join(data, "fault-native-adapter-removed"), []byte("armed"), 0600); err != nil {
				t.Fatal(err)
			}
			// The fault fires on the next packet the read pump delivers.
			if conn, err := fixture.dial(ctx, "tcp4", fixture.target); err == nil {
				conn.Close()
			}
			wait(t, fmt.Sprintf("loss %d consumed", loss), 15*time.Second, func() bool {
				_, err := os.Stat(filepath.Join(data, "fault-native-adapter-removed.consumed"))
				return err == nil
			})
			_ = os.Remove(filepath.Join(data, "fault-native-adapter-removed.consumed"))
			recovery := newNativeRecoveryTimer()
			if runtime.GOOS != "windows" && loss == 4 {
				// Linux counts every read fault as an ordinary failure, so this
				// is the fifth in ten minutes with the child crash above: the
				// latch must hold (spec §2) until the owner turns routing on.
				latched := waitRouting(t, c, "five failures latch routing off", 45*time.Second, func(s status) bool {
					return s.Routing == "error" && s.Error != nil && strings.Contains(*s.Error, "five failures")
				})
				time.Sleep(6 * time.Second) // longer than the 1/2/5 s backoff steps
				if s := getStatus(t, c); s.Routing != "error" || s.Instance != latched.Instance {
					t.Fatalf("latched routing restarted on its own: %+v", s)
				}
				j := readControlJournal(t, data)
				if len(j.Failures) < 5 {
					t.Fatalf("latched with fewer than five journaled failures: %+v", j)
				}
				t.Logf("NATIVE_CONTROL_LATCH failures=%d losses=%d status=%+v", len(j.Failures), len(j.Losses), latched)
				c.must(t, "routing", map[string]any{"on": true}, nil) // the owner's explicit retry clears the budget
				recovery = newNativeRecoveryTimer()
			}
			after := waitRouting(t, c, fmt.Sprintf("restart after loss %d", loss), 60*time.Second, func(s status) bool { return s.Routing == "on" && s.Instance != "" && s.Instance != before.Instance })
			j := readControlJournal(t, data)
			end, err := service.Query(service.Engine)
			t.Logf("NATIVE_CONTROL_LOSS n=%d old=%s new=%s restarted_after=%s failures=%d losses=%d query=%+v err=%v", loss, before.Instance, after.Instance, recovery.elapsed(), len(j.Failures), len(j.Losses), end, err)
			if runtime.GOOS != "windows" && loss == 4 {
				if len(j.Failures) != 0 || len(j.Losses) != 0 {
					t.Fatalf("the owner's retry did not reset the budget: %+v", j)
				}
			} else if runtime.GOOS == "windows" {
				// Windows: the genuine Wintun removal error exits 3 with cleanup
				// complete. Three are free; the fourth counts.
				wantFailures := failuresBefore
				if loss > 3 {
					wantFailures++
				}
				if len(j.Losses) != loss || len(j.Failures) != wantFailures {
					t.Fatalf("loss %d: failures=%d (want %d) losses=%d (want %d)", loss, len(j.Failures), wantFailures, len(j.Losses), loss)
				}
			} else if len(j.Failures) != failuresBefore+loss || len(j.Losses) != 0 {
				// Linux: a failed read pump is an ordinary failure (exit 1).
				t.Fatalf("loss %d: failures=%d (want %d) losses=%d", loss, len(j.Failures), failuresBefore+loss, len(j.Losses))
			}
		}
		echoExact(t, ctx, fixture, 1024)
	})
	t.Run("control-absent-past-the-lease-then-restored-within-70s", func(t *testing.T) {
		restore := disableRecovery(t)
		before := getStatus(t, c)
		control, err := service.Query(service.Control)
		if err != nil {
			t.Fatal(err)
		}
		killUnreset(t, control.PID)
		wait(t, "lease expiry stops the engine", 45*time.Second, func() bool { s, err := service.Query(service.Engine); return err == nil && s.Stopped })
		waitNativeCleanup(t, fixture, data, before.Instance)
		restore()
		recovery := newNativeRecoveryTimer()
		if err := service.Start(ctx, service.Control); err != nil {
			t.Fatal(err)
		}
		c = openClient(t, owner, false)
		after := waitRouting(t, c, "wanted routing restored", 70*time.Second, func(s status) bool { return s.Routing == "on" && s.Instance != "" && s.Instance != before.Instance })
		elapsed := recovery.elapsed()
		if elapsed > 70*time.Second {
			t.Fatal("wanted routing took longer than the 70 s bound", elapsed)
		}
		j := readControlJournal(t, data)
		t.Logf("NATIVE_CONTROL_RESTORE old=%s new=%s restored_after=%s bound=70s failures=%d losses=%d", before.Instance, after.Instance, elapsed, len(j.Failures), len(j.Losses))
		echoExact(t, ctx, fixture, 1024)
	})
	stop, cancelStop := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelStop()
	if err := service.Stop(stop, service.Control); err != nil {
		t.Fatal(err)
	}
	wait(t, "engine stopped with Control", 40*time.Second, func() bool { s, err := service.Query(service.Engine); return err == nil && s.Stopped })
	fixture.clean(t)
}
