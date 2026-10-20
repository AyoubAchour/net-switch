//go:build linux

package linux

import (
	"context"
	"fmt"
	"slices"

	"golang.org/x/sys/unix"
)

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
