package lifecycle_test

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/AyoubAchour/net-switch/tests/linux/topo"
	"golang.org/x/sys/unix"
)

func nativeImage(t *testing.T, pid uint32) string {
	t.Helper()
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func resumeNative(t *testing.T, pid uint32) {
	t.Helper()
	if err := unix.Kill(int(pid), unix.SIGCONT); err != nil {
		t.Error("resume native engine", err)
	}
}

func assertNativeCapture(t *testing.T, _ string, _ tunFixture) {
	t.Helper()
	for _, args := range [][]string{{"link", "show", "dev", "NetSwitch"}, {"-4", "rule", "show"}} {
		b, err := exec.Command("ip", append([]string{"-n", topo.DUT}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatal("native capture precondition", err, string(b))
		}
		if args[0] == "-4" && !strings.Contains(string(b), "iif lo") {
			t.Fatal("native capture rule missing", string(b))
		}
		t.Logf("NATIVE_CAPTURE %s", b)
	}
}

func waitNativeCleanup(t *testing.T, fixture tunFixture) {
	// systemd remains deactivating until ExecStopPost has completed, so the
	// Stopped observation in the caller already joined the cleanup command.
	fixture.clean(t)
}
