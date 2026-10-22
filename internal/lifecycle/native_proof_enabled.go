//go:build lifecycle_test

package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/host"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
)

// This fault only exists in hosted-test builds. The arm/hit/release files are
// in the verified SYSTEM/root-only store. No protocol operation enables it.
type stalledReader struct {
	platform.TunDevice
	data      string
	ioContext context.Context
}

// Preserve the native device's fast paths, cancellation and counters while
// interposing only the read pump. In particular, Linux stats must not vanish.
func (r *stalledReader) Stats() any {
	if device, ok := r.TunDevice.(interface{ Stats() any }); ok {
		return device.Stats()
	}
	return nil
}
func (r *stalledReader) BindIOContext(ctx context.Context) {
	r.ioContext = ctx
	if device, ok := r.TunDevice.(platform.TunIOContext); ok {
		device.BindIOContext(ctx)
	}
}
func (r *stalledReader) BeginClose() {
	if device, ok := r.TunDevice.(platform.TunCloseStarter); ok {
		device.BeginClose()
	}
}
func (r *stalledReader) RXChecksumVerified(p []byte) bool {
	device, ok := r.TunDevice.(platform.ChecksumVerifier)
	return ok && device.RXChecksumVerified(p)
}
func (r *stalledReader) WriteBatch(packets [][]byte) (int, error) {
	if device, ok := r.TunDevice.(platform.BatchWriter); ok {
		return device.WriteBatch(packets)
	}
	ctx := r.ioContext
	if ctx == nil {
		ctx = context.Background()
	}
	for i, p := range packets {
		if err := r.TunDevice.WritePacket(ctx, p); err != nil {
			return i, err
		}
	}
	return len(packets), nil
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
	options.Configure = func(server *protocol.Server, table *flows.Table) {
		server.TestFault = func(_ context.Context, b json.RawMessage) (any, error) {
			var request struct {
				Kind string `json:"kind"`
			}
			if err := json.Unmarshal(b, &request); err != nil {
				return nil, err
			}
			if request.Kind != "totals-capacity" {
				return nil, errors.New("unknown hosted native fault")
			}
			if err := table.SeedAccountingFixture(); err != nil {
				return nil, err
			}
			return table.Stats(), nil
		}
	}
	var ready atomic.Bool
	progress := options.Progress
	options.Progress = func(stage string) {
		if progress != nil {
			progress(stage)
		}
		if stage == "ready-callback-end" {
			ready.Store(true)
		}
		_ = os.WriteFile(filepath.Join(data, "native-startup-phase.txt"), []byte(time.Now().UTC().Format(time.RFC3339Nano)+" "+stage), 0600)
	}
	time.AfterFunc(25*time.Second, func() {
		if ready.Load() {
			return
		}
		b := make([]byte, 256<<10)
		n := runtime.Stack(b, true)
		_ = os.WriteFile(filepath.Join(data, "native-startup-stacks.txt"), b[:n], 0600)
	})
	options.WrapTun = func(tun platform.TunDevice) platform.TunDevice {
		return &stalledReader{TunDevice: tun, data: data}
	}
}

type nativeProofOutcome struct{}

func (nativeProofOutcome) Error() string       { return "hosted completed outcome 3" }
func (nativeProofOutcome) EngineExitCode() int { return 3 }
func nativeProofExit(data string) error {
	if _, err := os.Stat(filepath.Join(data, "fault-native-exit3")); err == nil {
		return nativeProofOutcome{}
	}
	return nil
}

func nativeProofRecovery(data string) error {
	if _, err := os.Stat(filepath.Join(data, "fault-native-recovery")); err == nil {
		return errors.New("hosted recovery failure before OS cleanup")
	}
	return nil
}
