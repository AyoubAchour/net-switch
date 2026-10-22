package lifecycle

import (
	"context"

	"github.com/AyoubAchour/net-switch/internal/engine/host"
	"github.com/AyoubAchour/net-switch/internal/engine/linux"
	"github.com/AyoubAchour/net-switch/internal/localipc"
)

func replaceNativeState(from, to string) error { return durableRename(from, to) }

func serveNative(ctx context.Context, data string, options host.Options) error {
	return linux.ServeHosted(ctx, localipc.DefaultPath("engine"), data, options, nil)
}

func cleanupNative(ctx context.Context, data string) error {
	return linux.RecoverReported(ctx, data, func() (func(error) error, error) { return recoveryOutcome(data) })
}
