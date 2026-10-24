package lifecycle_test

import (
	"os/exec"
	"strings"
	"testing"
)

// The installed engine unit never restarts itself; ExecStopPost cleans up and
// Control owns every restart (spec §3.4).
func assertEngineHasNoManagerRestart(t *testing.T) {
	t.Helper()
	b, err := exec.Command("systemctl", "show", "-p", "Restart", "-p", "ExecStopPost", "netswitch-engine.service").CombinedOutput()
	if err != nil {
		t.Fatal(err, string(b))
	}
	text := string(b)
	if !strings.Contains(text, "Restart=no") || !strings.Contains(text, "cleanup --engine") {
		t.Fatalf("engine unit must only clean up, never restart: %s", text)
	}
	t.Logf("NATIVE_CONTROL_RECOVERY_ACTIONS %s", strings.TrimSpace(text))
}
