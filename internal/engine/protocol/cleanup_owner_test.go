package protocol

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

type leaseCleanupOwner struct {
	*runtimeFake
	owned   bool
	failure error
}

func (r *leaseCleanupOwner) Stop(ctx context.Context) error {
	r.owned = platform.CleanupOwned(ctx)
	return r.failure
}

func TestLeaseFailureReturnsToLeaseReporter(t *testing.T) {
	s, base, _ := setup(t)
	r := &leaseCleanupOwner{runtimeFake: base, failure: errors.New("lease cleanup failed")}
	s.runtime = r
	s.expires = s.now().Add(-time.Second)
	if err := s.CheckLease(context.Background()); !errors.Is(err, r.failure) || !r.owned {
		t.Fatal("lease lost cleanup ownership or failure", err, r.owned)
	}
}
