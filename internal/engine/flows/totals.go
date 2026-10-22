package flows

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type totalEntry struct {
	id  string
	app bool
	Bytes
}

type totalsSnapshot struct {
	entries []totalEntry
	expires time.Time
	bytes   int64
}

type TotalsPage struct {
	Totals
	Cursor string `json:"cursor,omitempty"`
	Count  int    `json:"count"`
}

func (t *Table) expireSnapshots(now time.Time) {
	for id, s := range t.snapshots {
		if !now.Before(s.expires) {
			t.gauges.SnapshotBytes -= s.bytes
			delete(t.snapshots, id)
		}
	}
	for id, s := range t.totalSnapshots {
		if !now.Before(s.expires) {
			t.gauges.SnapshotBytes -= s.bytes
			delete(t.totalSnapshots, id)
		}
	}
}

// PageTotals freezes counters once, including closed flows, then pages that
// immutable value. It shares the flow snapshot count/byte budgets. Exhaustion
// returns an error before allocation; it never drops accounting entries.
func (t *Table) PageTotals(cursor string) (TotalsPage, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.expireSnapshots(now)
	var id uint64
	index := 0
	if cursor == "" {
		if len(t.snapshots)+len(t.totalSnapshots) >= t.limits.Snapshots {
			return TotalsPage{}, ErrBudget
		}
		// Reserve a conservative peak for both aggregation maps and sorted
		// entries, before allocating either. Duplicate live identities only
		// overcharge this bound. Keys are immutable, shared strings.
		bytes := int64(64)
		for id := range t.totals.Apps {
			bytes += 256 + int64(len(id))
		}
		for id := range t.totals.Lines {
			bytes += 256 + int64(len(id))
		}
		for _, f := range t.flows {
			if f.resolved {
				bytes += 512 + int64(len(f.record.Owner.AppID)+len(f.record.Line))
			}
		}
		if bytes > t.limits.SnapshotBytes-t.gauges.SnapshotBytes {
			return TotalsPage{}, ErrBudget
		}
		t.gauges.SnapshotBytes += bytes
		totals := t.totalsLocked()
		entries := make([]totalEntry, 0, len(totals.Apps)+len(totals.Lines))
		for id, b := range totals.Apps {
			entries = append(entries, totalEntry{id, true, b})
		}
		for id, b := range totals.Lines {
			entries = append(entries, totalEntry{id, false, b})
		}
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].app != entries[j].app {
				return entries[i].app
			}
			return entries[i].id < entries[j].id
		})
		if t.totalSnapshots == nil {
			t.totalSnapshots = map[uint64]*totalsSnapshot{}
		}
		t.nextSnapshot++
		id = t.nextSnapshot
		t.totalSnapshots[id] = &totalsSnapshot{entries, now.Add(10 * time.Second), bytes}
	} else {
		parts := strings.Split(cursor, ":")
		if len(parts) != 3 || parts[0] != "totals" {
			return TotalsPage{}, errors.New("invalid totals cursor")
		}
		var err error
		id, err = strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return TotalsPage{}, errors.New("invalid totals cursor")
		}
		index, err = strconv.Atoi(parts[2])
		if err != nil || index < 0 {
			return TotalsPage{}, errors.New("invalid totals cursor")
		}
	}
	s := t.totalSnapshots[id]
	if s == nil || index > len(s.entries) {
		return TotalsPage{}, errors.New("expired or invalid totals cursor")
	}
	end := min(index+64, len(s.entries))
	out := TotalsPage{Totals: Totals{Apps: map[string]Bytes{}, Lines: map[string]Bytes{}}, Count: len(s.entries)}
	for _, entry := range s.entries[index:end] {
		if entry.app {
			out.Apps[entry.id] = entry.Bytes
		} else {
			out.Lines[entry.id] = entry.Bytes
		}
	}
	if end < len(s.entries) {
		out.Cursor = fmt.Sprintf("totals:%d:%d", id, end)
	} else {
		t.gauges.SnapshotBytes -= s.bytes
		delete(t.totalSnapshots, id)
	}
	return out, nil
}
