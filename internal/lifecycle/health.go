package lifecycle

import (
	"context"
	"fmt"
	"time"
)

// The native engine can implement this boundary using an internal forwarding
// health check when it replaces the adapter. A successful response resets the
// whole window; snapshot latency is deliberately not an input.
type engineHealth interface {
	Health(context.Context) error
}

type healthWatch struct {
	failedFor time.Duration
}

func (w *healthWatch) check(ctx context.Context, engine engineHealth, now func() time.Time) error {
	started := now()
	probe, cancel := context.WithTimeout(ctx, 3*time.Second)
	err := engine.Health(probe)
	cancel()
	if err == nil {
		w.failedFor = 0
		return nil
	}
	// A single request that spans standby must not turn eight sleeping hours
	// into a full failure window before queued resume notifications run. Count
	// at most its three-second probe budget (at least one host watch tick).
	w.failedFor += min(max(now().Sub(started), time.Second), 3*time.Second)
	if w.failedFor >= 20*time.Second {
		return fmt.Errorf("routing engine health check failed continuously for 20 seconds: %w", err)
	}
	return nil
}
