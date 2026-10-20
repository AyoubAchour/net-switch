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
	failedSince time.Time
}

func (w *healthWatch) check(ctx context.Context, engine engineHealth, now func() time.Time) error {
	started := now()
	probe, cancel := context.WithTimeout(ctx, 3*time.Second)
	err := engine.Health(probe)
	cancel()
	if err == nil {
		w.failedSince = time.Time{}
		return nil
	}
	if w.failedSince.IsZero() {
		w.failedSince = started
	}
	if now().Sub(w.failedSince) >= 20*time.Second {
		return fmt.Errorf("routing engine health check failed continuously for 20 seconds: %w", err)
	}
	return nil
}
