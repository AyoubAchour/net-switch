//go:build lifecycle_test

package protocol

import (
	"context"
	"errors"

	"github.com/AyoubAchour/net-switch/internal/engine/policy"
)

func (s *Server) RestartForTest(ctx context.Context, r policy.Revision) error {
	runtime, ok := s.runtime.(interface {
		RestartForTest(context.Context, policy.Revision) error
	})
	if !ok {
		return errors.New("runtime has no hosted restart")
	}
	return runtime.RestartForTest(ctx, r)
}
