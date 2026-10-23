package flows

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const TotalsPageBytes = 512 << 10
const AccountingEntries = 65536

var ErrAccounting = errors.New("unacknowledged accounting capacity exhausted")

// Counter is cumulative within its generation. A new generation for the same
// app starts at zero only after the old, idle generation was acknowledged.
// Control persists the per-generation high-water marks before acknowledging.
type Counter struct {
	Bytes
	Generation string `json:"generation"`
}

type totalEntry struct {
	id  string
	app bool
	Counter
}
type totalsSnapshot struct {
	entries   []totalEntry
	expires   time.Time
	bytes     int64
	delivered int
	nonce     string
}
type TotalsPage struct {
	Apps     map[string]Counter `json:"apps"`
	Lines    map[string]Counter `json:"lines"`
	Cursor   string             `json:"cursor,omitempty"`
	Receipt  string             `json:"receipt"`
	Count    int                `json:"count"`
	Instance string             `json:"engineInstanceId,omitempty"`
}
type TotalsAck struct {
	Apps  int `json:"apps"`
	Lines int `json:"lines"`
}

type accountIdentity struct {
	app bool
	id  string
}

func accountKey(app bool, id string) accountIdentity { return accountIdentity{app, id} }

// Reserve on admission, so a close never needs to allocate an unbounded new
// identity. Existing flows and known identities remain usable while Control
// is behind; a new identity gets a classified refusal, never lost bytes.
func (t *Table) reserveAccounting(app, line string) bool {
	_, haveApp := t.totals.Apps[app]
	_, haveLine := t.totals.Lines[line]
	apps, lines := t.limits.AccountingApps, t.limits.AccountingLines
	if apps == 0 {
		apps = AccountingEntries
	}
	if lines == 0 {
		lines = AccountingEntries
	}
	if (!haveApp && len(t.totals.Apps) >= apps) || (!haveLine && len(t.totals.Lines) >= lines) {
		return false
	}
	needed := uint64(0)
	if !haveApp {
		needed++
	}
	if !haveLine {
		needed++
	}
	if ^uint64(0)-t.nextAccounting < needed {
		return false
	}
	if t.accountingIDs == nil {
		t.accountingIDs = map[accountIdentity]uint64{}
	}
	for _, entry := range []struct {
		app    bool
		id     string
		exists bool
	}{{true, app, haveApp}, {false, line, haveLine}} {
		if entry.exists {
			continue
		}
		t.nextAccounting++
		t.accountingIDs[accountKey(entry.app, entry.id)] = t.nextAccounting
		if entry.app {
			t.totals.Apps[entry.id] = Bytes{}
		} else {
			t.totals.Lines[entry.id] = Bytes{}
		}
	}
	return true
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
			t.gauges.TotalsSnapshotBytes -= s.bytes
			delete(t.totalSnapshots, id)
		}
	}
}

func totalsID(value string) (uint64, string, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 3 || parts[0] != "totals" || len(parts[2]) != 32 {
		return 0, "", errors.New("invalid totals receipt")
	}
	id, err := strconv.ParseUint(parts[1], 10, 64)
	return id, parts[2], err
}

func (t *Table) PageTotals(cursor string) (TotalsPage, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.expireSnapshots(now)
	var id uint64
	index := 0
	nonce := ""
	if cursor == "" {
		if len(t.totalSnapshots) >= t.limits.Snapshots {
			return TotalsPage{}, ErrBudget
		}
		// Account for maps, sorted entries and their immutable strings before
		// allocating. The retained identities themselves have admission caps.
		bytes := int64(64)
		for id := range t.totals.Apps {
			bytes += 320 + int64(len(id))
		}
		for id := range t.totals.Lines {
			bytes += 320 + int64(len(id))
		}
		for _, f := range t.flows {
			if f.resolved {
				bytes += 640 + int64(len(f.record.Owner.AppID)+len(f.record.Line))
			}
		}
		// Totals have their own slots and at most half the aggregate byte
		// budget. Unacked receipts cannot starve flow listing; Defaults reserves
		// enough in the other half for two maximum-size flow snapshots.
		if bytes > t.limits.SnapshotBytes/2-t.gauges.TotalsSnapshotBytes || bytes > t.limits.SnapshotBytes-t.gauges.SnapshotBytes {
			return TotalsPage{}, ErrBudget
		}
		var entropy [16]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			return TotalsPage{}, err
		}
		nonce = hex.EncodeToString(entropy[:])
		t.gauges.SnapshotBytes += bytes
		t.gauges.TotalsSnapshotBytes += bytes
		v := t.totalsLocked()
		entries := make([]totalEntry, 0, len(v.Apps)+len(v.Lines))
		for _, app := range []bool{true, false} {
			values := v.Lines
			if app {
				values = v.Apps
			}
			for key, n := range values {
				entries = append(entries, totalEntry{key, app, Counter{n, strconv.FormatUint(t.accountingIDs[accountKey(app, key)], 10)}})
			}
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
		t.totalSnapshots[id] = &totalsSnapshot{entries: entries, expires: now.Add(10 * time.Second), bytes: bytes, nonce: nonce}
	} else {
		parts := strings.Split(cursor, ":")
		if len(parts) != 4 {
			return TotalsPage{}, errors.New("invalid totals cursor")
		}
		var err error
		id, nonce, err = totalsID(strings.Join(parts[:3], ":"))
		if err != nil {
			return TotalsPage{}, err
		}
		index, err = strconv.Atoi(parts[3])
		if err != nil || index < 0 {
			return TotalsPage{}, errors.New("invalid totals cursor")
		}
	}
	s := t.totalSnapshots[id]
	if s == nil || s.nonce != nonce || index > len(s.entries) || index > s.delivered {
		return TotalsPage{}, errors.New("expired or nonsequential totals cursor")
	}
	out := TotalsPage{Apps: map[string]Counter{}, Lines: map[string]Counter{}, Receipt: fmt.Sprintf("totals:%d:%s", id, nonce), Count: len(s.entries)}
	end, size := index, 1024 // bounded envelope, both maps, cursor and receipt
	for end < len(s.entries) {
		entry := s.entries[end]
		key, _ := json.Marshal(entry.id)
		value, _ := json.Marshal(entry.Counter)
		needed := len(key) + len(value) + 2
		if size+needed > TotalsPageBytes {
			break
		}
		if entry.app {
			out.Apps[entry.id] = entry.Counter
		} else {
			out.Lines[entry.id] = entry.Counter
		}
		size += needed
		end++
	}
	s.delivered = max(s.delivered, end)
	if end < len(s.entries) {
		out.Cursor = fmt.Sprintf("%s:%d", out.Receipt, end)
	}
	return out, nil
}

// AckTotals is called only after Control durably consumes every page. A late
// ACK may retire only the exact idle generation and counter value it read.
// New traffic, a replacement generation, or a partial/expired read is safe.
func (t *Table) AckTotals(receipt string) (TotalsAck, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.expireSnapshots(t.now())
	id, nonce, err := totalsID(receipt)
	if err != nil {
		return TotalsAck{}, err
	}
	s := t.totalSnapshots[id]
	if s == nil || s.nonce != nonce || s.delivered != len(s.entries) {
		return TotalsAck{}, errors.New("totals receipt is expired or incomplete")
	}
	live := map[accountIdentity]bool{}
	for _, f := range t.flows {
		if f.resolved {
			live[accountKey(true, f.record.Owner.AppID)] = true
			live[accountKey(false, f.record.Line)] = true
		}
	}
	var result TotalsAck
	for _, entry := range s.entries {
		key := accountKey(entry.app, entry.id)
		if live[key] || strconv.FormatUint(t.accountingIDs[key], 10) != entry.Generation {
			continue
		}
		values := t.totals.Lines
		if entry.app {
			values = t.totals.Apps
		}
		if values[entry.id] != entry.Bytes {
			continue
		}
		if !entry.app && t.policy != nil && t.policy.HasLine(entry.id) {
			continue
		}
		delete(values, entry.id)
		delete(t.accountingIDs, key)
		if entry.app {
			result.Apps++
		} else {
			result.Lines++
		}
	}
	t.gauges.SnapshotBytes -= s.bytes
	t.gauges.TotalsSnapshotBytes -= s.bytes
	delete(t.totalSnapshots, id)
	return result, nil
}
