package lifecycle_test

import (
	"context"
	"testing"
)

func resetControlRecoveryWindow(*testing.T) {}
func enrollmentRestarts(t *testing.T, _ context.Context, _ actor, _ tunFixture) {
	t.Skip("systemd enrollment restart delay")
}
func controlCrashStorm(t *testing.T, _ context.Context, _ actor, _ tunFixture) {
	t.Skip("systemd crash recovery")
}
func controlRestartDelayDecays(t *testing.T, _ context.Context, _ actor, _ tunFixture) {
	t.Skip("systemd restart counter; the Windows service manager resets its failure count after 600 s")
}
