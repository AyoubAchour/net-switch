package lifecycle

import (
	"context"
	"errors"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/host"
	winengine "github.com/AyoubAchour/net-switch/internal/engine/windows"
	"golang.org/x/sys/windows"
)

func serveNative(ctx context.Context, data string, options host.Options) error {
	return winengine.ServeHosted(ctx, data, false, options)
}

func replaceNativeState(from, to string) error {
	return replaceNativeStateWith(from, to, durableRename)
}

// A status reader may briefly hold the destination. MoveFileEx refuses an
// open replacement even with delete sharing on current Windows. Retry only
// those conflicts, within 250 ms; a permanent permission error still fails.
func replaceNativeStateWith(from, to string, rename func(string, string) error) error {
	deadline := time.Now().Add(250 * time.Millisecond)
	for {
		err := rename(from, to)
		if (!errors.Is(err, windows.ERROR_ACCESS_DENIED) && !errors.Is(err, windows.ERROR_SHARING_VIOLATION)) || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func cleanupNative(ctx context.Context, data string) error {
	return winengine.RecoverReported(ctx, data, func() (func(error) error, error) { return recoveryOutcome(data) })
}
