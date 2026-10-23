//go:build lifecycle_test

package engine

import (
	"context"

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
