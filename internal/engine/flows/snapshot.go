package flows

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

type snapshot struct {
	records []Record
	expires time.Time
	bytes   int64
}
type Page struct {
	Flows  []Record `json:"flows"`
	Cursor string   `json:"cursor,omitempty"`
}

func (t *Table) Page(cursor string) (Page, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for id, s := range t.snapshots {
		if !now.Before(s.expires) {
			t.gauges.SnapshotBytes -= s.bytes
			delete(t.snapshots, id)
		}
	}
	var id uint64
	index := 0
	if cursor == "" {
		if len(t.snapshots) >= t.limits.Snapshots {
			return Page{}, ErrBudget
		}
		bytes := int64(64)
		count := 0
		for _, f := range t.flows {
			if f.resolved {
				count++
				bytes += int64(unsafe.Sizeof(Record{})) + int64(len(f.record.Owner.Path) + len(f.record.Owner.AppID) + len(f.record.Owner.Generation))
			}
		}
		if count > t.limits.SnapshotEntries || bytes > t.limits.SnapshotBytes-t.gauges.SnapshotBytes {
			return Page{}, ErrBudget
		}
		t.gauges.SnapshotBytes += bytes
		records := make([]Record, 0, count)
		for _, f := range t.flows {
			if f.resolved {
				records = append(records, f.record)
			}
		}
		sorted(records)
		t.nextSnapshot++
		id = t.nextSnapshot
		t.snapshots[id] = &snapshot{records: records, expires: now.Add(10 * time.Second), bytes: bytes}
	} else {
		parts := strings.Split(cursor, ":")
		if len(parts) != 2 {
			return Page{}, errors.New("invalid cursor")
		}
		var err error
		id, err = strconv.ParseUint(parts[0], 10, 64)
		if err != nil {
			return Page{}, errors.New("invalid cursor")
		}
		index, err = strconv.Atoi(parts[1])
		if err != nil || index < 0 {
			return Page{}, errors.New("invalid cursor")
		}
	}
	s := t.snapshots[id]
	if s == nil || index > len(s.records) {
		return Page{}, errors.New("expired or invalid cursor")
	}
	end := min(index+64, len(s.records))
	page := Page{Flows: append([]Record{}, s.records[index:end]...)}
	if end < len(s.records) {
		page.Cursor = fmt.Sprintf("%d:%d", id, end)
	} else {
		t.gauges.SnapshotBytes -= s.bytes
		delete(t.snapshots, id)
	}
	return page, nil
}
