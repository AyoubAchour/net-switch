package lifecycle_test

import (
	"context"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/internal/service"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func enrollmentRestarts(t *testing.T, ctx context.Context, owner actor, fixture tunFixture) {
	resetControlRecoveryWindow(t)
	if err := service.Start(ctx, service.Control); err != nil {
		t.Fatal(err)
	}
	c := openClient(t, owner, false)
	defer c.input.Close()
	c.must(t, "signin", nil, nil)
	wait(t, "routing before enrollment restarts", 30*time.Second, func() bool { return getStatus(t, c).Routing == "on" })
	stream := routedStream(t, ctx, fixture)
	defer stream.Close()
	for range 6 {
		before, err := service.Query(service.Control)
		if err != nil {
			t.Fatal(err)
		}
		if err := service.RequestRestart(ctx, service.Control); err != nil {
			t.Fatal(err)
		}
		wait(t, "intentional replacement stays prompt", 5*time.Second, func() bool {
			s, e := service.Query(service.Control)
			return e == nil && s.Running && s.PID != before.PID
		})
		fixture.exchange(t, stream)
		b, err := exec.Command("systemctl", "show", "--property=NRestarts", "--value", "netswitch.service").Output()
		n, parseErr := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil || parseErr != nil || n > 1 {
			t.Fatal("enrollment accumulated crash backoff", string(b), err, parseErr)
		}
	}
	if err := service.Stop(ctx, service.Control); err != nil {
		t.Fatal(err)
	}
}

func controlRestarts(t *testing.T) int {
	t.Helper()
	b, err := exec.Command("systemctl", "show", "--property=NRestarts", "--value", "netswitch.service").Output()
	n, parseErr := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || parseErr != nil {
		t.Fatal("read Control restart counter", string(b), err, parseErr)
	}
	return n
}

// controlRestartDelayDecays starts from accumulated crash state on purpose:
// a reset-failed before the case would hide that systemd's restart counter
// never decays during a healthy run. Four crashes put the next restart at
// RestartMaxDelaySec (60 s, past the 30 s lease); after Control has run
// healthy for its window it must clear the counter itself, and the next
// crash must restart in about a second.
func controlRestartDelayDecays(t *testing.T, ctx context.Context, owner actor, fixture tunFixture) {
	window := filepath.Join(testData(), "fault-restart-decay-seconds")
	if err := os.WriteFile(window, []byte("20"), 0600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(window)
	if err := service.Start(ctx, service.Control); err != nil {
		t.Fatal(err)
	}
	c := openClient(t, owner, false)
	defer c.input.Close()
	c.must(t, "signin", nil, nil)
	wait(t, "routing before accumulating crashes", 30*time.Second, func() bool { return getStatus(t, c).Routing == "on" })
	stream := routedStream(t, ctx, fixture)
	defer stream.Close()
	for i := 0; i < 4; i++ {
		s, err := service.Query(service.Control)
		if err != nil || !s.Running {
			t.Fatal("crash precondition", s, err)
		}
		killUnreset(t, s.PID)
		wait(t, "Control restart while accumulating crashes", 35*time.Second, func() bool {
			next, e := service.Query(service.Control)
			return e == nil && next.Running && next.PID != s.PID
		})
		fixture.exchange(t, stream)
	}
	accumulated := controlRestarts(t)
	if accumulated < 4 {
		t.Fatal("accumulated-state precondition: restart counter", accumulated)
	}
	t.Logf("accumulated %d automatic restarts; without decay the next crash would wait 60 s", accumulated)
	healthy := time.Now()
	wait(t, "Control clears its restart counter after a healthy run", 60*time.Second, func() bool { return controlRestarts(t) == 0 })
	cleared := time.Since(healthy)
	if cleared < 15*time.Second {
		t.Fatal("restart counter cleared before the healthy window", cleared)
	}
	s, err := service.Query(service.Control)
	if err != nil || !s.Running {
		t.Fatal("decay precondition", s, err)
	}
	crashed := time.Now()
	killUnreset(t, s.PID)
	wait(t, "prompt restart after a healthy run", 15*time.Second, func() bool {
		next, e := service.Query(service.Control)
		return e == nil && next.Running && next.PID != s.PID
	})
	restarted := time.Since(crashed)
	if restarted > 5*time.Second {
		t.Fatal("restart after decay still used the long delay", restarted)
	}
	fixture.exchange(t, stream)
	t.Logf("RESTART_DECAY accumulated=%d cleared_after=%s restart_after_decay=%s", accumulated, cleared.Round(time.Millisecond), restarted.Round(time.Millisecond))
}

func resetControlRecoveryWindow(t *testing.T) {
	t.Helper()
	if b, err := exec.Command("systemctl", "reset-failed", "netswitch.service").CombinedOutput(); err != nil {
		t.Fatal(err, string(b))
	}
	t.Log("isolated fault case: reset Control restart delay; start limiting is disabled")
}
func controlCrashStorm(t *testing.T, ctx context.Context, owner actor, fixture tunFixture) {
	t.Helper()
	resetControlRecoveryWindow(t)
	defer resetControlRecoveryWindow(t)
	if err := service.Start(ctx, service.Control); err != nil {
		t.Fatal(err)
	}
	c := openClient(t, owner, false)
	c.must(t, "signin", nil, nil)
	wait(t, "routing before crash storm", 30*time.Second, func() bool { return getStatus(t, c).Routing == "on" })
	stream := routedStream(t, ctx, fixture)
	defer stream.Close()
	for i := 0; i < 5; i++ {
		s, err := service.Query(service.Control)
		if err != nil || !s.Running {
			t.Fatal("crash-limit precondition", s, err)
		}
		killUnreset(t, s.PID)
		if i < 4 {
			wait(t, "Control restart with growing delay", 35*time.Second, func() bool {
				next, e := service.Query(service.Control)
				return e == nil && next.Running && next.PID != s.PID
			})
			fixture.exchange(t, stream)
		}
	}
	wait(t, "lease fails open during the long restart delay", 40*time.Second, func() bool {
		s, e := service.Query(service.Engine)
		return e == nil && s.Stopped
	})
	directTraffic(t, ctx, fixture)
	if info, err := os.Stat(localipc.DefaultPath("status")); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatal("activation socket disappeared", err)
	}
	desktop := owner.command(filepath.Join(os.Getenv("NETSWITCH_LIFECYCLE_DIR"), "netswitch-desktop"), "--background")
	if err := desktop.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = desktop.Process.Kill(); _ = desktop.Wait() }()
	wait(t, "Control recovers after storm without reset-failed", 75*time.Second, func() bool { s, e := service.Query(service.Control); return e == nil && s.Running })
	fresh := openClient(t, owner, false)
	defer fresh.input.Close()
	wait(t, "original desktop reconnects and routing recovers", 35*time.Second, func() bool {
		s := getStatus(t, fresh)
		return s.DesktopPID == uint32(desktop.Process.Pid) && s.Routing == "on"
	})
	t.Log("crash storm failed open; socket remained present and desktop recovered without a reset or reboot")
}
