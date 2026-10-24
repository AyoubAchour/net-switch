package usage

import (
	"math"
	"time"
	_ "time/tzdata"

	"github.com/AyoubAchour/net-switch/internal/lines"
)

const BusyBytesPerSecond = 256 * 1024
const PeakHalfLifeMS = 2 * 60 * 60000

func PeriodStart(cap *lines.Cap, now int64, location *time.Location) int64 {
	if location == nil {
		var err error
		location, err = LocalLocation()
		if err != nil {
			panic(err)
		} // Call LocalLocation at startup to report a configuration error.
	}
	date := time.UnixMilli(now).In(location)
	year, month, day := date.Date()
	if cap != nil && cap.Period == "day" {
		return localMidnight(year, month, day, location).UnixMilli()
	}
	reset := 1
	if cap != nil && cap.ResetDay != 0 {
		reset = max(1, min(cap.ResetDay, 28))
	}
	start := localMidnight(year, month, reset, location)
	if start.UnixMilli() > now {
		start = localMidnight(year, month-1, reset, location)
	}
	return start.UnixMilli()
}

// JS Date chooses the earlier instant in a fold and the pre-gap offset in a
// gap. Go time.Date makes no such guarantee. Enumerate the offsets around the
// wall date, keeping the earliest exact match or the first wall time after it.
func localMidnight(year int, month time.Month, day int, loc *time.Location) time.Time {
	wall := time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
	var exact, after time.Time
	var afterWall time.Time
	for hours := -48; hours <= 48; hours += 6 {
		_, offset := wall.Add(time.Duration(hours) * time.Hour).In(loc).Zone()
		candidate := wall.Add(-time.Duration(offset) * time.Second)
		local := candidate.In(loc)
		y, m, d := local.Date()
		h, min, sec := local.Clock()
		w := time.Date(y, m, d, h, min, sec, 0, time.UTC)
		if w.Equal(wall) && (exact.IsZero() || candidate.Before(exact)) {
			exact = candidate
		}
		if w.After(wall) && (after.IsZero() || w.Before(afterWall)) {
			after, afterWall = candidate, w
		}
	}
	if !exact.IsZero() {
		return exact
	}
	return after
}

type Entry struct {
	Bytes       float64 `json:"bytes"`
	PeriodStart float64 `json:"periodStart"`
}
type Counter struct {
	RX float64 `json:"rx"`
	TX float64 `json:"tx"`
}
type Saved struct {
	Lines map[string]Entry   `json:"lines"`
	Peaks map[string]float64 `json:"peaks"`
	// Routed holds the engine's exact per-app and per-line bytes (spec §5.10).
	// It is absent while the temporary adapter is the engine, so that record
	// keeps its 0.3.x shape. Caps keep counting the whole adapter.
	Routed *Routed `json:"routed,omitempty"`
}
type Usage struct {
	Saved
	Counters map[string]Counter
	PeakAt   map[string]int64
	Location *time.Location
}

func New(location *time.Location) *Usage {
	if location == nil {
		var err error
		location, err = LocalLocation()
		if err != nil {
			panic(err)
		}
	}
	return &Usage{Saved: Saved{Lines: map[string]Entry{}, Peaks: map[string]float64{}}, Counters: map[string]Counter{}, PeakAt: map[string]int64{}, Location: location}
}
func finite(n float64) bool { return !math.IsNaN(n) && !math.IsInf(n, 0) }
func (u *Usage) Load(saved map[string]any) {
	if items, ok := saved["lines"].(map[string]any); ok {
		for id, v := range items {
			m, ok := v.(map[string]any)
			if !ok {
				continue
			}
			bytes, b := m["bytes"].(float64)
			start, s := m["periodStart"].(float64)
			if b && s && finite(bytes) && finite(start) {
				u.Lines[id] = Entry{math.Max(0, bytes), start}
			}
		}
	}
	if items, ok := saved["peaks"].(map[string]any); ok {
		for id, v := range items {
			if n, ok := v.(float64); ok && finite(n) && n > 0 {
				u.Peaks[id] = n
			}
		}
	}
}
func (u *Usage) KeepOnly(ids []string) {
	keep := map[string]bool{}
	for _, id := range ids {
		keep[id] = true
	}
	for id := range u.Lines {
		if !keep[id] {
			delete(u.Lines, id)
		}
	}
	for id := range u.Peaks {
		if !keep[id] {
			delete(u.Peaks, id)
		}
	}
	for id := range u.Counters {
		if !keep[id] {
			delete(u.Counters, id)
		}
	}
	for id := range u.PeakAt {
		if !keep[id] {
			delete(u.PeakAt, id)
		}
	}
}
func (u *Usage) Ingest(items []lines.Line, counterOf func(lines.Line) *Counter, rateOf func(lines.Line) *float64, now int64) {
	for _, line := range items {
		start := float64(PeriodStart(line.Cap, now, u.Location))
		entry, exists := u.Lines[line.ID]
		if !exists || entry.PeriodStart != start {
			entry = Entry{0, start}
		}
		counter := counterOf(line)
		if counter != nil {
			if before, ok := u.Counters[line.ID]; ok {
				rx, tx := counter.RX-before.RX, counter.TX-before.TX
				if rx < 0 {
					rx = counter.RX
				}
				if tx < 0 {
					tx = counter.TX
				}
				entry.Bytes += rx + tx
			}
			u.Counters[line.ID] = *counter
		}
		u.Lines[line.ID] = entry
		u.NotePeak(line.ID, rateOf(line), now)
	}
}
func (u *Usage) NotePeak(id string, rate *float64, now int64) {
	if rate == nil || !finite(*rate) || *rate < BusyBytesPerSecond {
		delete(u.PeakAt, id)
		return
	}
	step := int64(0)
	if before, ok := u.PeakAt[id]; ok {
		step = min(now-before, 5000)
	}
	u.PeakAt[id] = now
	u.Peaks[id] = math.Max(*rate, float64(u.Peaks[id]*fade(float64(step)/PeakHalfLifeMS)))
}
func (u *Usage) Used(id string) *Entry {
	v, ok := u.Lines[id]
	if !ok {
		return nil
	}
	return &v
}
func (u *Usage) Exhausted(items []lines.Line, now int64) map[string]bool {
	result := map[string]bool{}
	for _, line := range items {
		if line.Cap == nil {
			continue
		}
		entry, ok := u.Lines[line.ID]
		if ok && entry.PeriodStart == float64(PeriodStart(line.Cap, now, u.Location)) && entry.Bytes >= line.Cap.Bytes {
			result[line.ID] = true
		}
	}
	return result
}
func (u *Usage) AutoWeights(items []lines.Line) map[string]float64 {
	sum, count := 0.0, 0
	for _, line := range items {
		if u.Peaks[line.ID] > 0 {
			sum += u.Peaks[line.ID]
			count++
		}
	}
	fallback := 1.0
	if count > 0 {
		fallback = sum / float64(count)
	}
	result := map[string]float64{}
	for _, line := range items {
		result[line.ID] = fallback
		if u.Peaks[line.ID] > 0 {
			result[line.ID] = u.Peaks[line.ID]
		}
	}
	return result
}
