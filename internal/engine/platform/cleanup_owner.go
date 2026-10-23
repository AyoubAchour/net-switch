package platform

import "context"

type cleanupOwnerKey struct{}

// WithCleanupOwner is an in-process call contract, never a wire option. The
// caller owns terminal delivery and must propagate cleanup failure to process
// exit. Nested cleanup must return its errors instead of racing that owner
// through a second generic-fatal notification.
func WithCleanupOwner(ctx context.Context) context.Context {
	return context.WithValue(ctx, cleanupOwnerKey{}, true)
}

func CleanupOwned(ctx context.Context) bool {
	owned, _ := ctx.Value(cleanupOwnerKey{}).(bool)
	return owned
}
