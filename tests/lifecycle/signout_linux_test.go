package lifecycle_test

import (
	"os/exec"
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
