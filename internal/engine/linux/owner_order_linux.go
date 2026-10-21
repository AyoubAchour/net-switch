//go:build linux

package linux

import (
	"context"
	"fmt"
	"slices"

	"golang.org/x/sys/unix"
)

type descriptorRange struct {
	first int64
	count int
}

// recentDescriptorRanges covers the recent 1,024-FD window, except the fresh
// interval (previousHigh, scannedHigh] already visited by this lookup. A high
// water mark is an ordering hint only: old descriptors still need fresh reads.
func recentDescriptorRanges(previousHigh, scannedHigh, extent int64) [2]descriptorRange {
	low := max(int64(0), extent-1023)
	first := max(low, scannedHigh+1)
	last := min(previousHigh, extent)
	return [2]descriptorRange{
		{first: first, count: int(max(int64(0), extent-first+1))},
		{first: low, count: int(max(int64(0), last-low+1))},
	}
}

// A large application scope can contain many children that have not opened
// sockets yet. Rank changed descriptor sets ahead of unchanged old holders,
// while retaining the strongest recent match. Counts never prove ownership
// or permit skipping a PID: every original candidate remains in the list.
func (o *Owners) prioritizeScope(ctx context.Context, pids, recent []uint32, uid uint32) {
	if len(pids) <= 16 || ctx.Err() != nil {
		return
	}
	first := 0
	if len(recent) != 0 && pids[0] == recent[0] {
		first = 1
	}
	type candidate struct {
		pid   uint32
		rank  int
		count int64
	}
	ordered := make([]candidate, 0, len(pids)-first)
	for _, pid := range pids[first:] {
		if ctx.Err() != nil {
			return
		}
		entry := candidate{pid: pid, rank: 2}
		var stat unix.Stat_t
		if unix.Stat(fmt.Sprintf("/proc/%d/fd", pid), &stat) == nil && (stat.Uid == uid || slices.Contains(recent, pid)) {
			o.mu.Lock()
			previous := o.windows[pid]
			o.mu.Unlock()
			entry.rank, entry.count = 1, stat.Size
			if previous.directory != stat.Ino || previous.fdCount != stat.Size {
				entry.rank = 0
			}
		}
		ordered = append(ordered, entry)
	}
	slices.SortStableFunc(ordered, func(a, b candidate) int {
		if a.rank != b.rank {
			return a.rank - b.rank
		}
		if a.rank == 0 {
			if a.count > b.count {
				return -1
			}
			if a.count < b.count {
				return 1
			}
		}
		return 0
	})
	for i, entry := range ordered {
		pids[first+i] = entry.pid
	}
}
