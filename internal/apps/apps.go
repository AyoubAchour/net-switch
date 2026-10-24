package apps

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apppath"
)

func AppKey(path string) string     { return apppath.Key(path) }
func LineOutbound(id string) string { return "line-" + id }
func LaneSelector(id string) string { return "lane-" + id }

type Connection struct {
	ID       string `json:"id"`
	Metadata struct {
		ProcessPath string `json:"processPath"`
	} `json:"metadata"`
	Download float64  `json:"download"`
	Upload   float64  `json:"upload"`
	Chains   []string `json:"chains"`
	Start    string   `json:"start"`
	// AppID is the engine's own identity for the owning app. On Windows it is
	// the normalised path; on Linux a sandboxed app is "flatpak:", "snap:" or
	// "appimage:" plus its id. The temporary adapter leaves it empty.
	AppID string `json:"appId,omitempty"`
}

// SandboxIdentity reports an engine identity no path rule can derive. A pin
// for such an app stores this exact value (design decision recorded in the
// spec): two sandboxes can share an executable path.
func SandboxIdentity(v string) bool {
	return strings.HasPrefix(v, "flatpak:") || strings.HasPrefix(v, "snap:") || strings.HasPrefix(v, "appimage:")
}

// SandboxLocation reports a Linux executable path inside a sandbox: the engine
// identifies such processes by sandbox identity, so a path pin there can only
// have been stored before the identity was known and must be reselected.
func SandboxLocation(path string) bool {
	for _, prefix := range []string{"/snap/", "/var/lib/flatpak/", "/app/", "/tmp/.mount_"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return strings.Contains(path, "/.local/share/flatpak/")
}

// PinNeedsReselection flags a path pin that cannot match the app the person
// meant: the path sits in a sandbox location, or the tracked app at that path
// is reported under a sandbox identity. Such a pin is kept, shown, and never
// routed by guess.
func PinNeedsReselection(pin Pin, trackedIdentity string) bool {
	if SandboxIdentity(pin.Path) {
		return false
	}
	return SandboxLocation(pin.Path) || SandboxIdentity(trackedIdentity)
}

func ConnectionLine(c *Connection) *string {
	if c == nil || len(c.Chains) == 0 || !strings.HasPrefix(c.Chains[0], "line-") {
		return nil
	}
	s := strings.TrimPrefix(c.Chains[0], "line-")
	return &s
}

type Pin struct {
	Path   string
	LineID string
}
type Pins []Pin

// JSON object order decides which saved version wins; a Go map loses that order.
func ParsePins(data []byte) (Pins, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		if err == nil {
			err = fmt.Errorf("appLines must be an object")
		}
		return nil, err
	}
	result := Pins{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return nil, err
		}
		var id string
		if err = d.Decode(&id); err != nil {
			return nil, err
		}
		result.Set(key.(string), id)
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("unexpected data after appLines")
	}
	keys := []string{}
	values := map[string]string{}
	for _, pin := range result {
		keys = append(keys, pin.Path)
		values[pin.Path] = pin.LineID
	}
	result = Pins{}
	for _, key := range objectKeys(keys) {
		result = append(result, Pin{key, values[key]})
	}
	return result, nil
}
func (pins Pins) normalized() ([]string, map[string]Pin) {
	order := []string{}
	result := map[string]Pin{}
	for _, pin := range pins {
		key := AppKey(pin.Path)
		if _, ok := result[key]; !ok {
			order = append(order, key)
		}
		result[key] = pin
	}
	return order, result
}

type Rate struct {
	Down float64 `json:"down"`
	Up   float64 `json:"up"`
}

func add(m map[string]Rate, id string, down, up float64, order *[]string) {
	if _, present := m[id]; !present && order != nil {
		*order = append(*order, id)
	}
	r := m[id]
	r.Down += down
	r.Up += up
	m[id] = r
}

// JavaScript enumerates array-index keys first, then other keys in insertion order.
// Addition order matters even when JSON object order does not.
func objectKeys(order []string) []string {
	result := append([]string{}, order...)
	index := func(s string) (uint64, bool) {
		n, err := strconv.ParseUint(s, 10, 32)
		return n, err == nil && n < 4294967295 && strconv.FormatUint(n, 10) == s
	}
	sort.SliceStable(result, func(i, j int) bool {
		a, ai := index(result[i])
		b, bi := index(result[j])
		return ai && (!bi || a < b)
	})
	return result
}
func total(m map[string]Rate, order []string) Rate {
	r := Rate{}
	for _, id := range objectKeys(order) {
		v := m[id]
		r.Down += v.Down
		r.Up += v.Up
	}
	return r
}
func smooth(before, next, weight float64) float64 {
	// The explicit conversions round each product, as JavaScript does. Without
	// them Go may fuse multiply and add on ARM64, changing the last bit.
	v := float64(before*(1-weight)) + float64(next*weight)
	if v < 1 {
		return 0
	}
	return v
}
func smoothRates(before, now map[string]Rate, beforeOrder, nowOrder []string, seconds, weight float64) (map[string]Rate, []string) {
	result := map[string]Rate{}
	order := []string{}
	seen := map[string]bool{}
	for _, id := range append(objectKeys(beforeOrder), objectKeys(nowOrder)...) {
		if seen[id] {
			continue
		}
		seen[id] = true
		raw, present := now[id]
		next := Rate{}
		if seconds != 0 && present {
			next = Rate{raw.Down / seconds, raw.Up / seconds}
		}
		v := Rate{smooth(before[id].Down, next.Down, weight), smooth(before[id].Up, next.Up, weight)}
		if v.Down > 0 || v.Up > 0 || present {
			result[id] = v
			order = append(order, id)
		}
	}
	return result, objectKeys(order)
}

type Row struct {
	Key  string `json:"key"`
	Path string `json:"path"`
	// Identity is the engine's sandbox identity for this app, empty for apps
	// the engine identifies by path.
	Identity    string             `json:"identity,omitempty"`
	Line        *string            `json:"line"`
	Rate        Rate               `json:"rate"`
	LineDown    map[string]float64 `json:"lineDown"`
	SortScore   float64            `json:"sortScore"`
	Connections map[string]int     `json:"connections"`
	Outside     *OutsideRow        `json:"outside"`
}
type app struct {
	Path        string
	Identity    string // sandbox identity reported by the engine, else empty
	Lines       map[string]Rate
	LineOrder   []string
	SortScore   float64
	LastSeen    int64
	Connections map[string]int
	IDs         map[string][]string
	IDOrder     []string
}
type Tracker struct {
	IdleKeepMS int64
	previous   map[string]Rate
	items      map[string]*app
	order      []string
	LineRates  map[string]Rate
	LastPollAt *int64
}

func NewTracker(options ...int64) *Tracker {
	idleKeepMS := int64(10 * 60000)
	if len(options) > 0 {
		idleKeepMS = options[0]
	}
	return &Tracker{IdleKeepMS: idleKeepMS, previous: map[string]Rate{}, items: map[string]*app{}, order: []string{}, LineRates: map[string]Rate{}}
}
func (t *Tracker) Reset() {
	t.previous = map[string]Rate{}
	for _, a := range t.items {
		a.Lines = map[string]Rate{}
		a.LineOrder = nil
		a.SortScore = 0
		a.Connections = map[string]int{}
		a.IDs = map[string][]string{}
		a.IDOrder = nil
	}
	t.LineRates = map[string]Rate{}
	t.LastPollAt = nil
}
func (t *Tracker) LineRate(id string) Rate { return t.LineRates[id] }
func (t *Tracker) Ingest(connections []Connection, now int64) {
	seconds := 0.0
	if t.LastPollAt != nil {
		seconds = math.Max(float64(now-*t.LastPollAt)/1000, 0.2)
	}
	nextBytes := map[string]Rate{}
	perApp := map[string]*app{}
	order := []string{}
	lineBytes := map[string]Rate{}
	for _, c := range connections {
		path := c.Metadata.ProcessPath
		key := AppKey(path)
		line := "unknown"
		if id := ConnectionLine(&c); id != nil {
			line = *id
		}
		down, up := 0.0, 0.0
		if previous, ok := t.previous[c.ID]; ok {
			down = math.Max(0, c.Download-previous.Down)
			up = math.Max(0, c.Upload-previous.Up)
		} else if t.LastPollAt != nil {
			start, err := time.Parse(time.RFC3339Nano, c.Start)
			if err == nil && start.UnixMilli() >= *t.LastPollAt-2000 {
				down, up = c.Download, c.Upload
			}
		}
		nextBytes[c.ID] = Rate{c.Download, c.Upload}
		entry := perApp[key]
		if entry == nil {
			entry = &app{Path: path, Lines: map[string]Rate{}, Connections: map[string]int{}, IDs: map[string][]string{}}
			perApp[key] = entry
			order = append(order, key)
		}
		if SandboxIdentity(c.AppID) {
			entry.Identity = c.AppID
		}
		add(entry.Lines, line, down, up, &entry.LineOrder)
		entry.Connections[line]++
		if _, ok := entry.IDs[line]; !ok {
			entry.IDOrder = append(entry.IDOrder, line)
		}
		entry.IDs[line] = append(entry.IDs[line], c.ID)
		add(lineBytes, line, down, up, nil)
	}
	for _, key := range order {
		if t.items[key] == nil {
			t.items[key] = &app{Path: perApp[key].Path, Lines: map[string]Rate{}, LastSeen: now}
			t.order = append(t.order, key)
		}
	}
	kept := []string{}
	for _, key := range t.order {
		a := t.items[key]
		entry := perApp[key]
		raw := map[string]Rate{}
		var rawOrder []string
		if entry != nil {
			raw = entry.Lines
			rawOrder = entry.LineOrder
		}
		a.Lines, a.LineOrder = smoothRates(a.Lines, raw, a.LineOrder, rawOrder, seconds, 0.6)
		sum := 0.0
		if seconds != 0 {
			r := total(raw, rawOrder)
			sum = (r.Down + r.Up) / seconds
		}
		a.SortScore = smooth(a.SortScore, sum, 0.25)
		if entry != nil {
			a.Connections = entry.Connections
			a.IDs = entry.IDs
			a.IDOrder = entry.IDOrder
			a.LastSeen = now
			a.Path = entry.Path
			if entry.Identity != "" {
				a.Identity = entry.Identity
			}
		} else {
			a.Connections = map[string]int{}
			a.IDs = map[string][]string{}
			a.IDOrder = nil
		}
		if len(a.Connections) == 0 && now-a.LastSeen > t.IdleKeepMS {
			delete(t.items, key)
		} else {
			kept = append(kept, key)
		}
	}
	t.order = kept
	t.LineRates = map[string]Rate{}
	for id, b := range lineBytes {
		r := Rate{}
		if seconds != 0 {
			r = Rate{b.Down / seconds, b.Up / seconds}
		}
		t.LineRates[id] = r
	}
	t.previous = nextBytes
	t.LastPollAt = &now
}

// IdentityOf is the engine's sandbox identity for a tracked app, or empty.
func (t *Tracker) IdentityOf(key string) string {
	if a := t.items[key]; a != nil {
		return a.Identity
	}
	return ""
}

func row(key string, a *app, pin *Pin) Row {
	r := Row{Key: key, Path: a.Path, Identity: a.Identity, Rate: total(a.Lines, a.LineOrder), LineDown: map[string]float64{}, SortScore: a.SortScore, Connections: map[string]int{}}
	if pin != nil {
		id := pin.LineID
		r.Line = &id
	}
	for id, v := range a.Lines {
		r.LineDown[id] = v.Down
	}
	for id, n := range a.Connections {
		r.Connections[id] = n
	}
	return r
}
func (t *Tracker) Snapshot(pins Pins) []Row {
	order, normalized := pins.normalized()
	result := []Row{}
	shown := map[string]bool{}
	for _, key := range t.order {
		a := t.items[key]
		var pin *Pin
		if p, ok := normalized[key]; ok {
			pin = &p
		} else if a.Identity != "" {
			// A sandbox pin is stored under the engine's identity, not the
			// shared path; it belongs to the tracked app with that identity.
			if p, ok := normalized[AppKey(a.Identity)]; ok {
				pin = &p
				shown[AppKey(a.Identity)] = true
			}
		}
		result = append(result, row(key, a, pin))
	}
	for _, key := range order {
		if t.items[key] == nil && !shown[key] {
			p := normalized[key]
			result = append(result, row(key, &app{Path: p.Path}, &p))
		}
	}
	return result
}
func (t *Tracker) ConnectionIDsFor(key, line string) []string {
	result := []string{}
	if a := t.items[key]; a != nil {
		result = append(result, a.IDs[line]...)
	}
	return result
}
func (t *Tracker) ConnectionIDsOffLine(key, line string) []string {
	result := []string{}
	if a := t.items[key]; a != nil {
		for _, id := range objectKeys(a.IDOrder) {
			if id != line {
				result = append(result, a.IDs[id]...)
			}
		}
	}
	return result
}

type OutsideSample struct {
	ID            string   `json:"id"`
	Path          string   `json:"path"`
	Line          string   `json:"line"`
	Down          *float64 `json:"down"`
	Up            *float64 `json:"up"`
	BeforeRouting bool     `json:"beforeRouting"`
}
type OutsideID struct {
	ID   string
	Line string
}
type OutsideApp struct {
	Key, Path               string
	Lines                   map[string]Rate
	LineOrder               []string
	Connections             int
	BeforeRouting, Measured bool
	IDs                     []OutsideID
	SortScore               float64
}
type OutsideRow struct {
	Connections   int            `json:"connections"`
	ByLine        map[string]int `json:"byLine"`
	BeforeRouting bool           `json:"beforeRouting"`
	Measured      bool           `json:"measured"`
	Rate          *Rate          `json:"rate"`
}
type OutsideTracker struct {
	previous map[string]Rate
	items    map[string]*OutsideApp
	order    []string
	lastAt   *int64
}

func NewOutsideTracker() *OutsideTracker { o := &OutsideTracker{}; o.Reset(); return o }
func (o *OutsideTracker) Reset() {
	o.previous = map[string]Rate{}
	o.items = map[string]*OutsideApp{}
	o.order = []string{}
	o.lastAt = nil
}
func (o *OutsideTracker) Get(key string) *OutsideApp { return o.items[key] }
func (o *OutsideTracker) Entries() []*OutsideApp {
	result := []*OutsideApp{}
	for _, key := range o.order {
		result = append(result, o.items[key])
	}
	return result
}
func (o *OutsideTracker) Ingest(samples []OutsideSample, now int64) {
	seconds := 0.0
	if o.lastAt != nil {
		seconds = math.Max(float64(now-*o.lastAt)/1000, 0.2)
	}
	next := map[string]Rate{}
	items := map[string]*OutsideApp{}
	order := []string{}
	for _, s := range samples {
		key := AppKey(s.Path)
		a := items[key]
		if a == nil {
			a = &OutsideApp{Key: key, Path: s.Path, Lines: map[string]Rate{}, BeforeRouting: true}
			items[key] = a
			order = append(order, key)
		}
		a.Connections++
		a.IDs = append(a.IDs, OutsideID{s.ID, s.Line})
		a.BeforeRouting = a.BeforeRouting && s.BeforeRouting
		if s.Down == nil {
			continue
		}
		a.Measured = true
		up := 0.0
		if s.Up != nil {
			up = *s.Up
		}
		if before, ok := o.previous[s.ID]; ok {
			add(a.Lines, s.Line, math.Max(0, *s.Down-before.Down), math.Max(0, up-before.Up), &a.LineOrder)
		}
		next[s.ID] = Rate{*s.Down, up}
	}
	for key, a := range items {
		before := o.items[key]
		old := map[string]Rate{}
		var oldOrder []string
		score := 0.0
		if before != nil {
			old = before.Lines
			oldOrder = before.LineOrder
			score = before.SortScore
		}
		sum := 0.0
		if seconds != 0 {
			r := total(a.Lines, a.LineOrder)
			sum = (r.Down + r.Up) / seconds
		}
		a.Lines, a.LineOrder = smoothRates(old, a.Lines, oldOrder, a.LineOrder, seconds, 0.6)
		a.SortScore = smooth(score, sum, 0.25)
	}
	o.items = items
	o.order = order
	o.previous = next
	o.lastAt = &now
}
func (o *OutsideTracker) IDsOffLine(key, line string) []string {
	result := []string{}
	if a := o.items[key]; a != nil {
		for _, id := range a.IDs {
			if id.Line != line {
				result = append(result, id.ID)
			}
		}
	}
	return result
}
func (o *OutsideTracker) IDsOf(key string) []string {
	result := []string{}
	if a := o.items[key]; a != nil {
		for _, id := range a.IDs {
			result = append(result, id.ID)
		}
	}
	return result
}
func MergeRows(routed []Row, outside *OutsideTracker, pins Pins) []Row {
	_, normalized := pins.normalized()
	result := append([]Row{}, routed...)
	seen := map[string]bool{}
	for _, r := range result {
		seen[r.Key] = true
	}
	for _, key := range outside.order {
		a := outside.items[key]
		if !seen[key] {
			var pin *Pin
			if p, ok := normalized[key]; ok {
				pin = &p
			}
			result = append(result, row(key, &app{Path: a.Path}, pin))
		}
	}
	for i := range result {
		r := &result[i]
		extra := outside.items[r.Key]
		if extra == nil {
			r.Outside = nil
			continue
		}
		active := false
		for _, n := range r.Connections {
			active = active || n > 0
		}
		if !active {
			r.Path = extra.Path
		}
		sum := total(extra.Lines, extra.LineOrder)
		r.Rate.Down += sum.Down
		r.Rate.Up += sum.Up
		down := map[string]float64{}
		for id, v := range r.LineDown {
			down[id] = v
		}
		for id, v := range extra.Lines {
			down[id] += v.Down
		}
		r.LineDown = down
		r.SortScore += extra.SortScore
		byLine := map[string]int{}
		for _, id := range extra.IDs {
			byLine[id.Line]++
		}
		r.Outside = &OutsideRow{extra.Connections, byLine, extra.BeforeRouting, extra.Measured, &sum}
	}
	return result
}

type Tuple struct {
	Local   string  `json:"local"`
	LPort   float64 `json:"lport"`
	Remote  string  `json:"remote"`
	RPort   float64 `json:"rport"`
	PID     float64 `json:"pid"`
	Created string  `json:"created"`
}

var outsidePattern = regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+):(\d+)>(\d+\.\d+\.\d+\.\d+):(\d+)\|(\d+)\|([^\r\n\x{2028}\x{2029}]+)$`)

func ParseOutsideID(id string) *Tuple {
	m := outsidePattern.FindStringSubmatch(id)
	if m == nil {
		return nil
	}
	number := func(s string) float64 { n, _ := strconv.ParseFloat(s, 64); return n }
	return &Tuple{m[1], number(m[2]), m[3], number(m[4]), number(m[5]), m[6]}
}
