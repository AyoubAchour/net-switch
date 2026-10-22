package lifecycle

import (
	"context"

	"github.com/AyoubAchour/net-switch/internal/engine/host"
	winengine "github.com/AyoubAchour/net-switch/internal/engine/windows"
)

func serveNative(ctx context.Context, data string, options host.Options) error {
	return winengine.ServeHosted(ctx, data, false, options)
}

func cleanupNative(_ context.Context, data string) error { return winengine.Recover(data) }
