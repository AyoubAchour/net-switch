//go:build !windows

package udp

import (
	"context"
	"time"
)

func waitReadRetry(ctx context.Context) bool {
	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
