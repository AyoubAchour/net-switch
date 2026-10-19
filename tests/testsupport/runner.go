// Package testsupport replays the public calls from each original Node test.
package testsupport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
	_ "time/tzdata"

	"github.com/AyoubAchour/net-switch/internal/apppath"
	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/linehealth"
	"github.com/AyoubAchour/net-switch/internal/lines"
	"github.com/AyoubAchour/net-switch/internal/settings"
	"github.com/AyoubAchour/net-switch/internal/updates"
	"github.com/AyoubAchour/net-switch/internal/usage"
)

type Call struct {
	Name   string            `json:"name"`
	ID     int               `json:"id"`
	Args   []json.RawMessage `json:"args"`
	Result json.RawMessage   `json:"result"`
	State  json.RawMessage   `json:"state"`
}
type Case struct {
	Name     string `json:"name"`
	Timezone string `json:"timezone,omitempty"`
	Calls    []Call `json:"calls"`
}
type Runner struct {
	objects  map[int]any
	entropy  int
	Location *time.Location
}

func New() *Runner { return &Runner{objects: map[int]any{}, Location: time.UTC} }
func arg[T any](args []json.RawMessage, index int, fallback T) T {
	if index >= len(args) || string(args[index]) == "null" {
		return fallback
	}
	var v T
	if err := json.Unmarshal(args[index], &v); err != nil {
		panic(err)
	}
	return v
}
func items(args []json.RawMessage, index int) []lines.Line {
	raw := arg(args, index, []json.RawMessage{})
	out := []lines.Line{}
	for _, b := range raw {
		l := lines.Line{Weight: 1}
		if err := json.Unmarshal(b, &l); err != nil {
			panic(err)
		}
		out = append(out, l)
	}
	return out
}
func set(args []json.RawMessage, index int) map[string]bool {
	out := map[string]bool{}
	for _, id := range arg(args, index, []string{}) {
		out[id] = true
	}
	return out
}
func pins(args []json.RawMessage, index int) apps.Pins {
	if index >= len(args) || string(args[index]) == "null" {
		return apps.Pins{}
	}
	v, err := apps.ParsePins(args[index])
	if err != nil {
		panic(err)
	}
	return v
}
func (r *Runner) id() string {
	r.entropy++
	return fmt.Sprintf("%02x%02x%02x", r.entropy, r.entropy, r.entropy)
}
func (r *Runner) Call(c Call) (any, any) {
	a := c.Args
	s := func(i int) string { return arg(a, i, "") }
	n := func(i int) int64 { return arg(a, i, int64(0)) }
	if c.Name == "LineHealth" {
		r.objects[c.ID] = &linehealth.Health{}
		return nil, nil
	}
	if c.Name == "Usage" {
		r.objects[c.ID] = usage.New(r.Location)
		return nil, nil
	}
	if c.Name == "AppTracker" {
		opts := arg(a, 0, map[string]int64{})
		r.objects[c.ID] = apps.NewTracker()
		if idle, present := opts["idleKeepMs"]; present {
			r.objects[c.ID] = apps.NewTracker(idle)
		}
		return nil, nil
	}
	if c.Name == "OutsideTracker" {
		r.objects[c.ID] = apps.NewOutsideTracker()
		return nil, nil
	}
	if h, ok := r.objects[c.ID].(*linehealth.Health); ok {
		var result any
		switch c.Name {
		case "reset":
			h.Reset()
		case "noteProbe":
			h.NoteProbe(arg[*bool](a, 0, nil), n(1))
		case "noteRoute":
			h.NoteRoute(arg[*bool](a, 0, nil), n(1))
		case "check":
			opts := arg(a, 2, map[string]bool{})
			result = h.Check(arg(a, 0, false), n(1), opts["tested"])
		case "restartKeeping":
			v := arg(a, 0, map[string]bool{})
			h.RestartKeeping(v["offline"], v["awaitingPass"], n(1))
		case "inDoubt":
			result = h.InDoubt()
		default:
			panic(c.Name)
		}
		return result, h
	}
	if u, ok := r.objects[c.ID].(*usage.Usage); ok {
		switch c.Name {
		case "set":
			switch s(0) {
			case "lines":
				u.Lines = arg(a, 1, map[string]usage.Entry{})
			case "peaks":
				u.Peaks = arg(a, 1, map[string]float64{})
			default:
				panic(s(0))
			}
		case "load":
			u.Load(arg(a, 0, map[string]any{}))
			return map[string]int{"ref": c.ID}, nil
		case "toJSON":
			return u.Saved, nil
		case "keepOnly":
			u.KeepOnly(arg(a, 0, []string{}))
		case "used":
			return u.Used(s(0)), nil
		case "autoWeights":
			return u.AutoWeights(items(a, 0)), nil
		case "notePeak":
			u.NotePeak(s(0), arg[*float64](a, 1, nil), n(2))
		case "exhausted":
			ls := items(a, 0)
			ex := u.Exhausted(ls, n(1))
			ids := []string{}
			for _, l := range ls {
				if ex[l.ID] {
					ids = append(ids, l.ID)
				}
			}
			return ids, nil
		case "ingest":
			counters := arg(a, 1, map[string]*usage.Counter{})
			rates := arg(a, 2, map[string]*float64{})
			u.Ingest(items(a, 0), func(l lines.Line) *usage.Counter { return counters[l.ID] }, func(l lines.Line) *float64 { return rates[l.ID] }, n(3))
		default:
			panic(c.Name)
		}
		return nil, nil
	}
	if t, ok := r.objects[c.ID].(*apps.Tracker); ok {
		switch c.Name {
		case "ingest":
			t.Ingest(arg(a, 0, []apps.Connection{}), n(1))
		case "snapshot":
			rows := t.Snapshot(pins(a, 0))
			return withoutOutside(rows), nil
		case "lineRate":
			return t.LineRate(s(0)), nil
		case "connectionIdsFor":
			return t.ConnectionIDsFor(s(0), s(1)), nil
		case "connectionIdsOffLine":
			return t.ConnectionIDsOffLine(s(0), s(1)), nil
		case "reset":
			t.Reset()
		default:
			panic(c.Name)
		}
		return nil, nil
	}
	if o, ok := r.objects[c.ID].(*apps.OutsideTracker); ok {
		switch c.Name {
		case "ingest":
			o.Ingest(arg(a, 0, []apps.OutsideSample{}), n(1))
		case "get":
			return outsideObject(o.Get(s(0))), nil
		case "entries":
			result := []any{}
			for _, a := range o.Entries() {
				result = append(result, outsideObject(a))
			}
			return result, nil
		case "idsOf":
			return o.IDsOf(s(0)), nil
		case "idsOffLine":
			return o.IDsOffLine(s(0), s(1)), nil
		case "reset":
			o.Reset()
		default:
			panic(c.Name)
		}
		return nil, nil
	}
	var result any
	switch c.Name {
	case "settingsPins":
		dir, err := os.MkdirTemp("", "netswitch-pins-")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		store := settings.New(dir, settings.Options{})
		if _, err = store.Update(map[string]any{"appLines": pins(a, 0)}); err != nil {
			panic(err)
		}
		if _, err = store.Load(); err != nil {
			panic(err)
		}
		if _, err = store.Change(func(v map[string]any) map[string]any {
			return map[string]any{"appLines": lines.PlaceWaitingApps(arg(a, 1, []any{}), v["appLines"].(apps.Pins), "b2")}
		}); err != nil {
			panic(err)
		}
		if _, err = store.Load(); err != nil {
			panic(err)
		}
		p := store.Values()["appLines"].(apps.Pins)
		result = map[string]any{"appLines": p, "rows": withoutOutside(apps.NewTracker().Snapshot(p))}
	case "sharePorts":
		shares := lines.SharesFromWeights(items(a, 0), arg(a, 1, map[string]any{}))
		result = map[string]any{"shares": shares, "ports": lines.AssignPorts(shares)}
	case "usageSequence":
		u := usage.New(r.Location)
		u.Load(arg(a, 0, map[string]any{}))
		steps := arg(a, 2, []struct {
			Now      int64                     `json:"now"`
			Counters map[string]*usage.Counter `json:"counters"`
			Rates    map[string]*float64       `json:"rates"`
		}{})
		out := []json.RawMessage{}
		for _, step := range steps {
			ls := items(a, 1)
			u.Ingest(ls, func(l lines.Line) *usage.Counter { return step.Counters[l.ID] }, func(l lines.Line) *float64 { return step.Rates[l.ID] }, step.Now)
			b, err := json.Marshal(map[string]any{"saved": u.Saved, "exhausted": u.Exhausted(ls, step.Now), "weights": u.AutoWeights(ls)})
			if err != nil {
				panic(err)
			}
			out = append(out, b)
		}
		result = out
	case "usageLoad":
		u := usage.New(r.Location)
		u.Load(arg(a, 0, map[string]any{}))
		result = u.Saved
	case "outsideSequence":
		tracker := apps.NewOutsideTracker()
		steps := arg(a, 0, []struct {
			Samples []apps.OutsideSample `json:"samples"`
			Now     int64                `json:"now"`
		}{})
		out := []any{}
		for _, step := range steps {
			tracker.Ingest(step.Samples, step.Now)
			out = append(out, apps.MergeRows(nil, tracker, nil))
		}
		result = out
	case "appSequence":
		tracker := apps.NewTracker()
		steps := arg(a, 0, []struct {
			Connections []apps.Connection `json:"connections"`
			Now         int64             `json:"now"`
		}{})
		out := []any{}
		for _, step := range steps {
			tracker.Ingest(step.Connections, step.Now)
			out = append(out, withoutOutside(tracker.Snapshot(nil)))
		}
		result = out
	case "appKey":
		result = apps.AppKey(s(0))
	case "appPathPattern":
		result = apppath.Pattern(s(0), apppath.Windows)
	case "lineOutbound":
		result = apps.LineOutbound(s(0))
	case "laneSelector":
		result = apps.LaneSelector(s(0))
	case "connectionLine":
		result = apps.ConnectionLine(arg[*apps.Connection](a, 0, nil))
	case "parseOutsideId":
		result = apps.ParseOutsideID(s(0))
	case "mergeRows":
		ref := arg(a, 1, map[string]int{})
		result = apps.MergeRows(arg(a, 0, []apps.Row{}), r.objects[ref["ref"]].(*apps.OutsideTracker), pins(a, 2))
	case "normalizeLines":
		result = lines.NormalizeLines(arg[any](a, 0, nil))
	case "validCap":
		result = lines.ValidCap(arg[any](a, 0, nil))
	case "laneTarget":
		result = lines.LaneTarget(items(a, 0), s(1), arg(a, 2, map[string]bool{}), set(a, 3))
	case "sharingLines":
		ls := items(a, 0)
		sharing := lines.SharingLines(ls, set(a, 1))
		raw := arg(a, 0, []any{})
		out := []any{}
		for _, l := range sharing {
			for i, item := range ls {
				if l.ID == item.ID {
					out = append(out, raw[i])
					break
				}
			}
		}
		result = out
	case "isOpenLine":
		result = lines.IsOpenLine(arg(a, 0, lines.Line{}), set(a, 1))
	case "sharesFromWeights":
		result = lines.SharesFromWeights(items(a, 0), arg(a, 1, map[string]any{}))
	case "lineLabel":
		result = lines.LineLabel(arg(a, 0, map[string]any{}))
	case "uniqueLabel":
		result = lines.UniqueLabel(s(0), items(a, 1))
	case "newLine":
		result = lines.NewLine(arg(a, 0, map[string]any{}), items(a, 1), r.id)
	case "pickFirstAdapter":
		result = lines.PickFirstAdapter(arg(a, 0, []map[string]any{}))
	case "migrateSettings":
		m := lines.MigrateSettings(arg(a, 0, map[string]any{}), r.id)
		if m != nil {
			v := map[string]any{"lines": m.Lines, "appLines": m.AppLines, "waitingApps": m.WaitingApps}
			for _, key := range lines.LegacyKeys {
				v[key] = nil
			}
			result = v
		}
	case "placeWaitingApps":
		result = lines.PlaceWaitingApps(arg(a, 0, []any{}), pins(a, 1), s(2))
	case "periodStart":
		result = usage.PeriodStart(arg[*lines.Cap](a, 0, nil), n(1), r.Location)
	case "parseVersion":
		result = updates.ParseVersion(s(0))
	case "isNewer":
		result = updates.IsNewer(s(0), s(1))
	case "offerFrom":
		result = updates.OfferFrom(arg(a, 0, map[string]any{}), s(1), arg(a, 2, "x64"))
	case "nativeArchitecture":
		result = "x64"
	default:
		panic("unknown call: " + c.Name)
	}
	return result, nil
}
func withoutOutside(rows []apps.Row) []map[string]any {
	b, _ := json.Marshal(rows)
	var result []map[string]any
	_ = json.Unmarshal(b, &result)
	for _, r := range result {
		delete(r, "outside")
	}
	return result
}
func outsideObject(a *apps.OutsideApp) any {
	if a == nil {
		return nil
	}
	ids := []map[string]string{}
	for _, id := range a.IDs {
		ids = append(ids, map[string]string{"id": id.ID, "line": id.Line})
	}
	return map[string]any{"key": a.Key, "path": a.Path, "lines": a.Lines, "connections": a.Connections, "beforeRouting": a.BeforeRouting, "measured": a.Measured, "ids": ids, "sortScore": a.SortScore}
}
func Run(t *testing.T, file string) {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var cases []Case
	if err = json.Unmarshal(b, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			r := New()
			if c.Timezone != "" {
				var err error
				r.Location, err = time.LoadLocation(c.Timezone)
				if err != nil {
					t.Fatal(err)
				}
			}
			for i, call := range c.Calls {
				actual, state := r.Call(call)
				compare(t, call.Result, actual, fmt.Sprintf("call %d %s", i, call.Name))
				if call.State != nil {
					compare(t, call.State, state, fmt.Sprintf("state after %d %s", i, call.Name))
				}
			}
		})
	}
}
func compare(t *testing.T, want json.RawMessage, got any, label string) {
	t.Helper()
	var expected, actual any
	if err := json.Unmarshal(want, &expected); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &actual); err != nil {
		t.Fatal(err)
	}
	root := ""
	if strings.HasSuffix(label, "sharesFromWeights") {
		root = "shares"
	}
	if strings.HasSuffix(label, "placeWaitingApps") {
		root = "appLines"
	}
	expected, actual = ordered(want, root), ordered(b, root)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("%s\nwant %s\n got %s", label, want, b)
	}
}

// Decode policy objects into ordered pairs before DeepEqual can erase order.
func ordered(raw json.RawMessage, key string) any {
	raw = bytes.TrimSpace(raw)
	if len(raw) > 0 && raw[0] == '{' {
		d := json.NewDecoder(bytes.NewReader(raw))
		_, _ = d.Token()
		pairs := []any{}
		object := map[string]any{}
		for d.More() {
			token, err := d.Token()
			if err != nil {
				panic(err)
			}
			name := token.(string)
			var value json.RawMessage
			if err := d.Decode(&value); err != nil {
				panic(err)
			}
			next := ordered(value, name)
			object[name] = next
			pairs = append(pairs, []any{name, next})
		}
		if key == "appLines" || key == "shares" {
			return pairs
		}
		return object
	}
	if len(raw) > 0 && raw[0] == '[' {
		var items []json.RawMessage
		_ = json.Unmarshal(raw, &items)
		result := []any{}
		for _, item := range items {
			result = append(result, ordered(item, ""))
		}
		return result
	}
	var value any
	_ = json.Unmarshal(raw, &value)
	return value
}
