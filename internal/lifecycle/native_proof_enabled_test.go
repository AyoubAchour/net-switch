//go:build lifecycle_test

package lifecycle

import (
	"context"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
)

type proofDevice struct {
	*testfake.Tun
	bound   context.Context
	batches int
	closing bool
}

func (d *proofDevice) Stats() any                         { return "native counters" }
func (d *proofDevice) BindIOContext(ctx context.Context)  { d.bound = ctx }
func (d *proofDevice) BeginClose()                        { d.closing = true }
func (d *proofDevice) RXChecksumVerified([]byte) bool     { return true }
func (d *proofDevice) WriteBatch(p [][]byte) (int, error) { d.batches++; return len(p), nil }

func TestNativeReadFaultPreservesDeviceDiagnosticsAndFastPaths(t *testing.T) {
	d := &proofDevice{Tun: testfake.NewTun()}
	defer d.Close()
	r := &stalledReader{TunDevice: d}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.BindIOContext(ctx)
	if d.bound != ctx || r.Stats() != "native counters" || !r.RXChecksumVerified(nil) {
		t.Fatal("read fault hid the native device contract")
	}
	n, err := r.WriteBatch([][]byte{[]byte("first"), []byte("second")})
	if err != nil || n != 2 || d.batches != 1 {
		t.Fatal("read fault changed batch output", n, err, d.batches)
	}
	r.BeginClose()
	if !d.closing {
		t.Fatal("read fault hid native teardown")
	}
}
