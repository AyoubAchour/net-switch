//go:build lifecycle_test

package lifecycle

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/host"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

// This fault only exists in hosted-test builds. The arm/hit/release files are
// in the verified SYSTEM/root-only store. No protocol operation enables it.
type stalledReader struct {
	platform.TunDevice
	data string
}

func (r *stalledReader) ReadPacket(ctx context.Context, b []byte) (int, error) {
	n, err := r.TunDevice.ReadPacket(ctx, b)
	if err != nil {
		return n, err
	}
	arm := filepath.Join(r.data, "fault-native-forwarding")
	if os.Rename(arm, arm+".consumed") != nil {
		return n, nil
	}
	if err := Save(filepath.Join(r.data, "native-forwarding-hit.json"), map[string]any{"pid": os.Getpid(), "bytes": n}); err != nil {
		return 0, err
	}
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(filepath.Join(r.data, "native-forwarding-release")); err == nil {
			return n, nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-tick.C:
		}
	}
}

func configureNativeProof(data string, options *host.Options) {
	options.WrapTun = func(tun platform.TunDevice) platform.TunDevice {
		return &stalledReader{TunDevice: tun, data: data}
	}
}
