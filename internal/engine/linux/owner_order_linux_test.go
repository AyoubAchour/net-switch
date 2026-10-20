//go:build linux

package linux

import (
	"context"
	"os"
	"slices"
	"testing"
)

func TestScopeRankingRetainsEveryCandidateAndStrongRecentHint(t *testing.T) {
	o := newTestOwners(t)
	pids := make([]uint32, 17)
	for i := range pids {
		pids[i] = uint32(1000000000 + i)
	}
	self := uint32(os.Getpid())
	pids[len(pids)-1] = self
	before := slices.Clone(pids)
	recent := []uint32{pids[0]}
	o.prioritizeScope(context.Background(), pids, recent, uint32(os.Geteuid()))
	if pids[0] != recent[0] || pids[1] != self {
		t.Fatalf("ranking lost the recent or changed candidate: %v", pids)
	}
	slices.Sort(before)
	slices.Sort(pids)
	if !slices.Equal(before, pids) {
		t.Fatal("ranking omitted or duplicated a candidate")
	}
}
