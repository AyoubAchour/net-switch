//go:build windows

package udp

import (
	"context"
	"time"

	"github.com/AyoubAchour/net-switch/internal/winclock"
)

func waitReadRetry(ctx context.Context) bool {
	return winclock.System.Wait(ctx, time.Millisecond) == nil
}
