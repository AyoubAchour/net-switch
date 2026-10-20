//go:build linux

package linux

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRecentDescriptorRangesRetainHolesWithoutRepeatingFreshReads(t *testing.T) {
	for _, bounds := range [][3]int64{
		{1151, 1663, 2065}, // failed cold-holder reuse: fd 1801 was read after a repeated prefix
		{1151, 1151, 2065}, // no new-descriptor pass yet
		{2065, 2577, 2065}, // only old holes remain in the recent window
		{0, 512, 2065},     // fresh work lies wholly before the recent window
		{1500, 2200, 2065},
		{0, 128, 128},
	} {
		previous, scanned, extent := bounds[0], bounds[1], bounds[2]
		visits := map[int64]int{}
		spans := recentDescriptorRanges(previous, scanned, extent)
		for _, span := range spans {
			if span.count < 0 || span.count > 1024 {
				t.Fatalf("unbounded descriptor range for %v: %+v", bounds, span)
			}
			for fd := span.first; fd < span.first+int64(span.count); fd++ {
				visits[fd]++
			}
		}
		for fd := max(int64(0), extent-1023); fd <= extent; fd++ {
			want := 1
			if fd > previous && fd <= scanned {
				want = 0 // already freshly inspected by this lookup
			}
			if visits[fd] != want {
				t.Fatalf("%v: fd %d visited %d times, want %d; ranges=%+v", bounds, fd, visits[fd], want, spans)
			}
		}
		if bounds == [3]int64{1151, 1663, 2065} && (spans[0].first != 1664 || spans[0].first+int64(spans[0].count) <= 1801) {
			t.Fatalf("reused fd 1801 must precede older holes: %+v", spans)
		}
	}
}

func TestHolderTimeoutBeforeScanKeepsSearchContext(t *testing.T) {
	o := newTestOwners(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	_, err := o.holders(ctx, socketRow{inode: 123, uid: 456})
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "uid=456 inode=123") || !strings.Contains(err.Error(), "pids=0 fds=0") {
		t.Fatalf("early timeout lost the search context: %v", err)
	}
}

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
