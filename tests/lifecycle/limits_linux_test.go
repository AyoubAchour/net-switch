package lifecycle_test

import (
	"context"
	"github.com/AyoubAchour/net-switch/internal/service"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func resetControlRecoveryWindow(t *testing.T) {
	t.Helper()
	if b, err := exec.Command("systemctl", "reset-failed", "netswitch.service").CombinedOutput(); err != nil {
		t.Fatal(err, string(b))
	}
	t.Log("isolated fault case: reset Control's start counter; installed five-starts-per-minute limit is unchanged")
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
			wait(t, "limited Control restart", 15*time.Second, func() bool {
				next, e := service.Query(service.Control)
				return e == nil && next.Running && next.PID != s.PID
			})
			checkEcho(t, stream)
		}
	}
	wait(t, "Control reaches installed start limit", 10*time.Second, func() bool {
		b, err := exec.Command("systemctl", "show", "--property=Result", "--value", "netswitch.service").Output()
		return err == nil && strings.TrimSpace(string(b)) == "start-limit-hit"
	})
	wait(t, "lease fails open after Control hits restart limit", 40*time.Second, func() bool { s, e := service.Query(service.Engine); return e == nil && s.Stopped })
	directEcho(t, echo)
	t.Log("five Control starts exhausted the installed rate limit; engine lease cleaned up without an infinite restart loop")
}
