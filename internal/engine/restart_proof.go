//go:build lifecycle_test

package engine

import (
	"context"
	"errors"

	"github.com/AyoubAchour/net-switch/internal/engine/policy"
)

// Hosted regression of an in-process forwarding generation change. Bypass
// the service runtime's terminal Stop, exactly as a recoverable pump failure
// does; product builds have no such method.
func (e *Engine) RestartForTest(ctx context.Context, r policy.Revision) error {
	if err := e.Stop(ctx); err != nil {
		return err
	}
	_, err := e.Start(ctx, r)
	return err
}

func (e *Engine) IdleErrorForTest(ctx context.Context) error {
	if err := e.Stop(ctx); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lastError = errors.New("hosted idle configuration error")
	e.live.Store(&liveState{status: "error", lastError: e.lastError.Error()})
	return nil
}
