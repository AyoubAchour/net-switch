package usage

import (
	"encoding/json"
	"math"
	"sort"
)

// RoutedBound caps the identities kept per kind. It equals the engine's own
// retained-set cap (spec §5.10), so no identity the engine can still report is
// ever evicted; only identities absent from a complete read fold into Other.
const RoutedBound = 65536

// RoutedKeep is how many absent identities stay listed individually after a
// complete read before the smallest fold into Other.
const RoutedKeep = 4096

// RoutedEntry is one identity's exact routed bytes. Up and Down accumulate
// across engine instances and accounting generations. Mark* and Generation
// are the high-water marks of the current generation in the current engine
// instance: the engine's cumulative counter minus the mark is what is new.
type RoutedEntry struct {
	Up         uint64 `json:"up"`
	Down       uint64 `json:"down"`
	Generation string `json:"generation,omitempty"`
	MarkUp     uint64 `json:"markUp,omitempty"`
	MarkDown   uint64 `json:"markDown,omitempty"`
}

// RoutedBytes is a plain up/down pair.
type RoutedBytes struct {
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

// Routed is the durable consumer of the engine's paged accounting. It is
// committed before every acknowledgement, so a crash between the commit and
// the ack re-reads counters that are at or above the marks (no double count),
// and a crash after the ack sees retired identities return with a new
// generation (no loss). An instance change drops every mark: a new engine
// starts all counters at zero.
type Routed struct {
	Instance string                  `json:"engineInstanceId,omitempty"`
	Apps     map[string]*RoutedEntry `json:"apps"`
	Lines    map[string]*RoutedEntry `json:"lines"`
	Other    RoutedBytes             `json:"other"`
	// Folded counts identities whose exact entries were folded into Other.
	Folded uint64 `json:"folded,omitempty"`
}

func NewRouted() *Routed {
	return &Routed{Apps: map[string]*RoutedEntry{}, Lines: map[string]*RoutedEntry{}}
}

// Counter is the engine's cumulative counter within one generation.
type RoutedCounter struct {
	Up, Down   uint64
	Generation string
}

// Absorb merges one page. It returns whether anything changed.
func (r *Routed) Absorb(instance string, apps, lines map[string]RoutedCounter) bool {
	changed := false
	if instance != r.Instance {
		r.Instance = instance
		for _, set := range []map[string]*RoutedEntry{r.Apps, r.Lines} {
			for _, e := range set {
				e.Generation, e.MarkUp, e.MarkDown = "", 0, 0
			}
		}
		changed = true
	}
	changed = absorb(r.Apps, apps) || changed
	changed = absorb(r.Lines, lines) || changed
	return changed
}

func absorb(set map[string]*RoutedEntry, page map[string]RoutedCounter) bool {
	changed := false
	for id, c := range page {
		e := set[id]
		if e == nil {
			e = &RoutedEntry{}
			set[id] = e
			changed = true
		}
		var up, down uint64
		if e.Generation == c.Generation && e.Generation != "" {
			// Within a generation the engine's counter only grows. A smaller
			// reading would mean a counter the engine restarted silently; take
			// it whole rather than lose it, which stays visible in the marks.
			up, down = c.Up-min(c.Up, e.MarkUp), c.Down-min(c.Down, e.MarkDown)
		} else {
			up, down = c.Up, c.Down
		}
		if up != 0 || down != 0 || e.Generation != c.Generation || e.MarkUp != c.Up || e.MarkDown != c.Down {
			changed = true
		}
		e.Up, e.Down = saturating(e.Up, up), saturating(e.Down, down)
		e.Generation, e.MarkUp, e.MarkDown = c.Generation, c.Up, c.Down
	}
	return changed
}

func saturating(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

// Compact runs after a complete read. Identities the engine no longer reports
// cannot double count later (a returning identity starts a new generation), so
// beyond RoutedKeep of them the smallest fold into Other. Present identities
// are never folded: their marks are still needed.
func (r *Routed) Compact(presentApps, presentLines map[string]bool) bool {
	changed := false
	for _, set := range []struct {
		entries map[string]*RoutedEntry
		present map[string]bool
	}{{r.Apps, presentApps}, {r.Lines, presentLines}} {
		absent := []string{}
		for id := range set.entries {
			if !set.present[id] {
				absent = append(absent, id)
			}
		}
		if len(absent) <= RoutedKeep {
			continue
		}
		sort.Slice(absent, func(i, j int) bool {
			a, b := set.entries[absent[i]], set.entries[absent[j]]
			if a.Up+a.Down != b.Up+b.Down {
				return a.Up+a.Down < b.Up+b.Down
			}
			return absent[i] < absent[j]
		})
		for _, id := range absent[:len(absent)-RoutedKeep] {
			e := set.entries[id]
			r.Other.Up, r.Other.Down = saturating(r.Other.Up, e.Up), saturating(r.Other.Down, e.Down)
			r.Folded++
			delete(set.entries, id)
			changed = true
		}
	}
	return changed
}

// LoadRouted decodes the routed section of a usage record with exact integers.
// The rest of the record goes through the JavaScript-shaped decoder, whose
// float64 numbers would lose exactness above 2^53. Absent or invalid routed
// data yields nil: the record then starts over, which the marks make safe.
func LoadRouted(file []byte) *Routed {
	var saved struct {
		Routed *Routed `json:"routed"`
	}
	if err := json.Unmarshal(file, &saved); err != nil || saved.Routed == nil {
		return nil
	}
	r := saved.Routed
	if r.Apps == nil {
		r.Apps = map[string]*RoutedEntry{}
	}
	if r.Lines == nil {
		r.Lines = map[string]*RoutedEntry{}
	}
	for _, set := range []map[string]*RoutedEntry{r.Apps, r.Lines} {
		for id, e := range set {
			if e == nil {
				delete(set, id)
			}
		}
	}
	return r
}
