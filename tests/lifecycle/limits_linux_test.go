package lifecycle_test

import (
	"context"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/internal/service"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func resetControlRecoveryWindow(t *testing.T) {
	t.Helper()
	if b, err := exec.Command("systemctl", "reset-failed", "netswitch.service").CombinedOutput(); err != nil {
		t.Fatal(err, string(b))
	}
	t.Log("isolated fault case: reset Control restart delay; start limiting is disabled")
}
func controlStartLimit(t *testing.T, ctx context.Context, owner actor, echo string) {
	t.Helper()
	resetControlRecoveryWindow(t)
	defer resetControlRecoveryWindow(t)
	if err := service.Start(ctx, service.Control); err != nil {
		t.Fatal(err)
	}
	c := openClient(t, owner, false)
	c.must(t, "signin", nil, nil)
	wait(t, "routing before crash storm", 30*time.Second, func() bool { return getStatus(t, c).Routing == "on" })
	var session struct{ Token, URL string }
	c.must(t, "session", nil, &session)
	stream := proxyStream(t, session.URL, session.Token, echo)
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
			checkEcho(t, stream)
		}
	}
	wait(t, "lease fails open during the long restart delay", 40*time.Second, func() bool {
		s, e := service.Query(service.Engine)
		return e == nil && s.Stopped
	})
	directEcho(t, echo)
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
