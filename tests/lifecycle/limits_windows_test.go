package lifecycle_test

import (
	"context"
	"testing"
)

func resetControlRecoveryWindow(*testing.T) {}
func controlStartLimit(t *testing.T, _ context.Context, _ actor, _ string) {
	t.Skip("systemd rate limiter")
}
