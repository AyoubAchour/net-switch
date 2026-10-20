package lifecycle_test

import (
	"context"
	"github.com/AyoubAchour/net-switch/internal/service"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func ownerSignout(t *testing.T, c *client, owner actor) {
	a := owner.(*linuxActor)
	if getStatus(t, c).Routing != "on" {
		t.Fatal("routing precondition")
	}
	if b, err := exec.Command("loginctl", "disable-linger", a.name).CombinedOutput(); err != nil {
		t.Fatal(err, string(b))
	}
	defer func() {
		if b, err := exec.Command("loginctl", "enable-linger", a.name).CombinedOutput(); err != nil {
			t.Error(err, string(b))
		}
	}()
	wait(t, "last logind owner session ends", 20*time.Second, func() bool { return getStatus(t, c).Routing == "off" })
	if b, err := exec.Command("loginctl", "enable-linger", a.name).CombinedOutput(); err != nil {
		t.Fatal(err, string(b))
	}
	c.must(t, "signin", nil, nil)
	wait(t, "next owner sign-in restores routing", 30*time.Second, func() bool { return getStatus(t, c).Routing == "on" })
	t.Log("real logind lingering owner ended: routing stopped; next sign-in recovered")
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
