package lifecycle_test

import (
	"context"
	"testing"
)

func resetControlRecoveryWindow(*testing.T) {}
func enrollmentRestarts(t *testing.T, _ context.Context, _ actor, _ string) {
	t.Skip("systemd enrollment restart delay")
}
func controlCrashStorm(t *testing.T, _ context.Context, _ actor, _ string) {
	t.Skip("systemd crash recovery")
}
