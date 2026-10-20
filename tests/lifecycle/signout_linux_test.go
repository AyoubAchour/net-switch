package lifecycle_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/service"
)

func ownerSignout(t *testing.T, c *client, owner actor) {
	if !hosted() {
		t.Skip("logind sessions run only on disposable hosted runners")
	}
	a := owner.(*linuxActor)
	if getStatus(t, c).Routing != "on" {
		t.Fatal("routing precondition")
	}
	requireLeftoverSessions(t)
	first := openLogindLogin(t, a, "first")
	last := openLogindLogin(t, a, "last")
	first.assertState(t, "active", "online")
	last.assertState(t, "active", "online")
	if first.info.Session == last.info.Session {
		t.Fatal("the two PAM logins reused one session")
	}
	if b, err := exec.Command("loginctl", "disable-linger", a.name).CombinedOutput(); err != nil {
		t.Fatal(err, string(b))
	}
	defer func() {
		if b, err := exec.Command("loginctl", "enable-linger", a.name).CombinedOutput(); err != nil {
			t.Error(err, string(b))
		}
	}()
	if b, err := exec.Command("loginctl", "show-user", a.uid, "--property=Linger", "--value").CombinedOutput(); err != nil || strings.TrimSpace(string(b)) != "no" {
		t.Fatal("linger-disabled precondition", err, string(b))
	}
	first.logout(t)
	first.waitClosing(t)
	assertRoutingOn(t, c, 3*time.Second)
	last.assertState(t, "active", "online")
	last.logout(t)
	last.waitClosing(t)
	wait(t, "last PAM logout clears routing despite leftover processes", 20*time.Second, func() bool { return getStatus(t, c).Routing == "off" })
	// These assertions prevent scope cleanup (rather than our state check)
	// from making the regression pass. Both logged-out scopes must remain.
	first.assertState(t, "closing")
	last.assertState(t, "closing")
	if b, err := exec.Command("loginctl", "enable-linger", a.name).CombinedOutput(); err != nil {
		t.Fatal(err, string(b))
	}
	c.must(t, "signin", nil, nil)
	wait(t, "linger permits owner sign-in after logout", 30*time.Second, func() bool { return getStatus(t, c).Routing == "on" })
	assertRoutingOn(t, c, 3*time.Second)
	first.assertState(t, "closing")
	last.assertState(t, "closing")
	t.Log("real PAM logins: one remaining session retained routing; last logout stopped routing while both closing scopes and their processes survived; linger restored routing")
}

func assertRoutingOn(t *testing.T, c *client, duration time.Duration) {
	t.Helper()
	for until := time.Now().Add(duration); time.Now().Before(until); {
		if s := getStatus(t, c); s.Routing != "on" {
			t.Fatal("owner still present but routing stopped", s)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func cliActivation(t *testing.T, owner actor) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := service.Stop(ctx, service.Control); err != nil {
		t.Fatal(err)
	}
	if s, err := service.Query(service.Control); err != nil || !s.Stopped {
		t.Fatal("Control stopped precondition", s, err)
	}
	command := owner.command(filepath.Join(os.Getenv("NETSWITCH_LIFECYCLE_DIR"), "netswitchctl"), "start")
	if b, err := command.CombinedOutput(); err != nil {
		t.Fatal("CLI failed to activate stopped Control", err, string(b))
	}
	c := openClient(t, owner, false)
	defer c.input.Close()
	wait(t, "CLI activated Control and routing", 30*time.Second, func() bool { return getStatus(t, c).Routing == "on" })
	if err := service.Stop(ctx, service.Control); err != nil {
		t.Fatal(err)
	}
}
