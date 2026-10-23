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
	// Counted is on a full listing's first page only (PageAll).
	Counted *Counted `json:"counted,omitempty"`
}

// Counted is the table's own admission count, read under the same lock as a
// full snapshot. Each count equals the matching listed records unless an
// admission charge leaked or a record outlived its charge.
type Counted struct {
	Flows      int `json:"flows"`
	UDP        int `json:"udp"`
	Handshakes int `json:"handshakes"`
}

// Page lists the flows whose owner is resolved: the routed flows Control
// shows and closes.
func (t *Table) Page(cursor string) (Page, error) { return t.page(cursor, false) }

// PageAll lists every admitted flow, including handshakes and UDP sessions
// whose owner lookup still runs (Unresolved), with the table's counts on the
// first page. Per-flow detail belongs here, under the snapshot budget, not in
// the aggregate stats reply.
func (t *Table) PageAll(cursor string) (Page, error) { return t.page(cursor, true) }

func (t *Table) page(cursor string, all bool) (Page, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.expireSnapshots(now)
	var id uint64
	index := 0
	var counted *Counted
	if cursor == "" {
		if len(t.snapshots)+len(t.totalSnapshots) >= t.limits.Snapshots {
			return Page{}, ErrBudget
		}
		listed := func(f *ticket) bool { return !f.retired && (all || f.resolved) }
		bytes := int64(64)
		count := 0
		for _, f := range t.flows {
			if listed(f) {
				count++
				bytes += int64(unsafe.Sizeof(Record{})) + int64(len(f.record.Owner.Path)+len(f.record.Owner.AppID)+len(f.record.Owner.Generation)+len(f.record.Line)+len(f.record.Lane))
			}
		}
		if count > t.limits.SnapshotEntries || bytes > t.limits.SnapshotBytes-t.gauges.SnapshotBytes {
			return Page{}, ErrBudget
		}
		t.gauges.SnapshotBytes += bytes
		records := make([]Record, 0, count)
		for _, f := range t.flows {
			if listed(f) {
				records = append(records, f.snapshotRecord())
			}
		}
		sorted(records)
		t.nextSnapshot++
		id = t.nextSnapshot
		t.snapshots[id] = &snapshot{records: records, expires: now.Add(10 * time.Second), bytes: bytes}
		if all {
			counted = &Counted{Flows: t.gauges.Flows, UDP: t.gauges.UDP, Handshakes: t.gauges.Handshakes}
		}
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
	page := Page{Flows: append([]Record{}, s.records[index:end]...), Counted: counted}
	if end < len(s.records) {
		page.Cursor = fmt.Sprintf("%d:%d", id, end)
	} else {
		t.gauges.SnapshotBytes -= s.bytes
		delete(t.snapshots, id)
	}
	return page, nil
}
