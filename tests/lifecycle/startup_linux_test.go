package lifecycle_test

import (
	"github.com/AyoubAchour/net-switch/internal/lifecycle"
	"os/exec"
	"sync"
	"testing"
)

func blockDesktopActivation(t *testing.T, _ lifecycle.Config) func() {
	if b, err := exec.Command("systemctl", "stop", "netswitch.socket").CombinedOutput(); err != nil {
		t.Fatal(err, string(b))
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			if b, err := exec.Command("systemctl", "start", "netswitch.socket").CombinedOutput(); err != nil {
				t.Fatal(err, string(b))
			}
		})
	}
}
