//go:build windows

package winengine

import (
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/AyoubAchour/net-switch/internal/wintun"
)

const AdapterLostExitCode = 2
const AdapterLostReason = "adapter lost"

// AdapterLostError is returned only after successful cleanup and resource
// closure. It remains distinguishable without a controller connection. A
// cleanup failure instead returns an ordinary error (exit status 1).
type AdapterLostError struct{ Cause error }

func (e *AdapterLostError) Error() string     { return fmt.Sprintf("%s: %v", AdapterLostReason, e.Cause) }
func (e *AdapterLostError) Unwrap() error     { return e.Cause }
func (*AdapterLostError) EngineExitCode() int { return AdapterLostExitCode }

type adapterLoss struct {
	cause atomic.Pointer[AdapterLostError]
	ready chan error
}

func newAdapterLoss() *adapterLoss { return &adapterLoss{ready: make(chan error, 1)} }

// Called under Engine.mu: only latch/enqueue, never enter the protocol lock or
// call Engine.Stop. Both pumps can report the same loss. This latch belongs to
// one engine instance, which exits after loss and never rebuilds in-process.
func (l *adapterLoss) handle(err error) bool {
	if !errors.Is(err, wintun.ErrAdapterRemoved) {
		return false
	}
	if l.cause.CompareAndSwap(nil, &AdapterLostError{Cause: err}) {
		l.ready <- err // reserved single slot; the winning sender cannot block
	}
	return true
}

func adapterLossResult(cause, cleanup error) error {
	if cleanup != nil {
		return fmt.Errorf("adapter lost; engine shutdown failed: %w", cleanup)
	}
	return &AdapterLostError{Cause: cause}
}
