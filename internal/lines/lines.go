package lines

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strconv"

	"github.com/AyoubAchour/net-switch/internal/apps"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
)

type Cap struct {
	Bytes    float64 `json:"bytes"`
	Period   string  `json:"period"`
	ResetDay int     `json:"resetDay,omitempty"`
}
type Line struct {
	ID      string  `json:"id"`
	Alias   string  `json:"alias"`
	GUID    *string `json:"guid"`
	Label   string  `json:"label"`
	Kind    *string `json:"kind"`
	Metered bool    `json:"metered"`
	Strict  bool    `json:"strict"`
	Cap     *Cap    `json:"cap"`
	Weight  float64 `json:"weight"`
}

func (line Line) MarshalJSON() ([]byte, error) {
	type plain Line
	return js.Marshal(struct {
		plain
		Label json.RawMessage `json:"label"`
	}{plain(line), js.MarshalString(line.Label)})
}

func textPointer(v any) *string {
	s, ok := v.(string)
	if !ok || s == "" {
		return nil
	}
	return &s
}
func ValidCap(v any) *Cap {
	m := js.Object(v)
	if m == nil {
		return nil
	}
	b, exists := m["bytes"]
	if !exists {
		return nil
	}
	n := js.Number(b)
	if math.IsNaN(n) || math.IsInf(n, 0) || n <= 0 {
		return nil
	}
	rounded := n
	if n != math.Trunc(n) {
		rounded = math.Floor(n)
		if n-rounded >= 0.5 {
			rounded++
		}
	}
	c := &Cap{Bytes: rounded, Period: "day"}
	if m["period"] != "day" {
		c.Period, c.ResetDay = "month", 1
		d := math.Trunc(js.Number(js.Default(m["resetDay"], float64(1))))
		if d >= 1 && d <= 28 {
			c.ResetDay = int(d)
		}
	}
	return c
}

var idPattern = regexp.MustCompile(`^[0-9a-f]{1,16}$`)

func NormalizeLines(v any) []Line {
	result := []Line{}
	seen := map[string]bool{}
	items, _ := v.([]any)
	for _, item := range items {
		m := js.Object(item)
		id, alias := js.Text(m["id"]), js.Text(m["alias"])
		if !idPattern.MatchString(id) || alias == "" || seen[id] {
			continue
		}
		label := js.Trim(js.Text(m["label"]))
		if label == "" {
			label = alias
		} else {
			label = js.UTF16Slice(label, 40)
		}
		kind := textPointer(m["kind"])
		if kind != nil && *kind != "wired" && *kind != "wifi" && *kind != "phone" {
			kind = nil
		}
		weight := 1.0
		if js.Finite(m["weight"]) && js.Number(m["weight"]) >= 0 {
			weight = js.Number(m["weight"])
		}
		result = append(result, Line{id, alias, textPointer(m["guid"]), label, kind, m["metered"] == true, m["strict"] == true && len(result) > 0, ValidCap(m["cap"]), weight})
		seen[id] = true
	}
	return result
}
func IsOpenLine(line Line, exhausted map[string]bool) bool {
	return !line.Strict && !exhausted[line.ID]
}
func SharingLines(lines []Line, exhausted map[string]bool) []Line {
	result := []Line{}
	for i, line := range lines {
		if (i == 0 && !exhausted[line.ID]) || (i != 0 && IsOpenLine(line, exhausted)) {
			result = append(result, line)
		}
	}
	return result
}
func LaneTarget(lines []Line, home string, up, exhausted map[string]bool) *string {
	found := false
	for _, line := range lines {
		if line.ID == home {
			found = true
		}
	}
	if !found {
		return nil
	}
	if up[home] && !exhausted[home] {
		return &home
	}
	for _, line := range lines {
		if line.ID != home && up[line.ID] && IsOpenLine(line, exhausted) {
			id := line.ID
			return &id
		}
	}
	return &home
}
func SharesFromWeights(lines []Line, weights map[string]any) Shares {
	result := Shares{}
	if len(lines) == 0 {
		return result
	}
	raw, exact, counts := make([]float64, len(lines)), make([]float64, len(lines)), make([]float64, len(lines))
	total := 0.0
	for i, line := range lines {
		v := js.Default(weights[line.ID], line.Weight)
		n := js.Number(v)
		if math.IsNaN(n) {
			n = 0
		}
		raw[i] = math.Max(0, n)
		total += raw[i]
	}
	left := 20.0
	order := make([]int, len(lines))
	for i := range lines {
		exact[i] = 20 / float64(len(lines))
		if total > 0 {
			exact[i] = raw[i] / total * 20
		}
		counts[i] = math.Max(1, math.Floor(exact[i]))
		left -= counts[i]
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := exact[order[i]], exact[order[j]]
		return a-math.Floor(a) > b-math.Floor(b)
	})
	for i := 0; left > 0; i = (i + 1) % len(order) {
		counts[order[i]]++
		left--
	}
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool { return counts[order[i]] > counts[order[j]] })
	for i := 0; left < 0 && i < len(order)*20; i++ {
		k := order[i%len(order)]
		if counts[k] > 1 {
			counts[k]--
			left++
		}
	}
	for i, line := range lines {
		result = append(result, Share{line.ID, float64(counts[i]) / 20})
	}
	// Object.entries enumerates canonical array-index keys before other IDs.
	sort.SliceStable(result, func(i, j int) bool {
		a, ea := strconv.ParseUint(result[i].ID, 10, 32)
		b, eb := strconv.ParseUint(result[j].ID, 10, 32)
		ai := ea == nil && a < 4294967295 && strconv.FormatUint(a, 10) == result[i].ID
		bi := eb == nil && b < 4294967295 && strconv.FormatUint(b, 10) == result[j].ID
		return ai && (!bi || a < b)
	})
	return result
}
func LineLabel(adapter map[string]any) string {
	if adapter == nil {
		return "Connection"
	}
	switch adapter["kind"] {
	case "wifi":
		return "Wi-Fi"
	case "phone":
		return "Phone"
	case "wired":
		return "Cable"
	}
	return js.Text(adapter["alias"])
}
func UniqueLabel(label string, lines []Line) string {
	used := map[string]bool{}
	for _, line := range lines {
		used[line.Label] = true
	}
	if !used[label] {
		return label
	}
	for n := 2; ; n++ {
		next := label + " " + js.String(n)
		if !used[next] {
			return next
		}
	}
}

type IDSource func() string

func PickFirstAdapter(adapters []map[string]any) map[string]any {
	var best map[string]any
	metric := func(a map[string]any) float64 {
		return js.Number(js.Default(a["routeMetric"], float64(0))) + js.Number(js.Default(a["metric"], float64(9999)))
	}
	for _, a := range adapters {
		if !js.Truth(a["connected"]) || js.Truth(a["virtual"]) {
			continue
		}
		if best == nil || metric(a) < metric(best) || (metric(a) == metric(best) && a["kind"] == "wired" && best["kind"] != "wired") {
			best = a
		}
	}
	return best
}
func RandomID() string {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func NewLine(adapter map[string]any, lines []Line, source IDSource) Line {
	if source == nil {
		source = RandomID
	}
	taken := map[string]bool{}
	for _, line := range lines {
		taken[line.ID] = true
	}
	id := source()
	for taken[id] {
		id = source()
	}
	return Line{ID: id, Alias: js.Text(adapter["alias"]), GUID: textPointer(adapter["guid"]), Label: UniqueLabel(LineLabel(adapter), lines), Kind: textPointer(adapter["kind"]), Metered: adapter["kind"] == "phone", Weight: 1}
}

var LegacyKeys = []string{"mainAlias", "mainGuid", "secondAlias", "secondGuid", "secondLabel", "secondKind", "secondApps", "cableApps"}

type Migration struct {
	Lines       []MigratedLine `json:"lines"`
	AppLines    apps.Pins      `json:"appLines"`
	WaitingApps []string       `json:"waitingApps,omitempty"`
}

// Migration copies legacy values verbatim; NormalizeLines is a separate step.
// In particular, empty GUIDs and non-string legacy fields must survive the copy.
type MigratedLine struct {
	ID      string  `json:"id"`
	Alias   any     `json:"alias"`
	GUID    any     `json:"guid"`
	Label   any     `json:"label"`
	Kind    any     `json:"kind"`
	Metered bool    `json:"metered"`
	Strict  bool    `json:"strict"`
	Cap     *Cap    `json:"cap"`
	Weight  float64 `json:"weight"`
}

// The caller deletes LegacyKeys when applying the changes; JSON has no undefined.
func MigrateSettings(values map[string]any, source IDSource) *Migration {
	if existing, ok := values["lines"].([]any); ok && len(existing) > 0 {
		return nil
	}
	if !js.Truth(values["mainAlias"]) && !js.Truth(values["secondAlias"]) {
		return nil
	}
	m := &Migration{Lines: []MigratedLine{}, AppLines: apps.Pins{}}
	if source == nil {
		source = RandomID
	}
	nextID := func() string {
		for {
			id := source()
			found := false
			for _, line := range m.Lines {
				if id == line.ID {
					found = true
				}
			}
			if !found {
				return id
			}
		}
	}
	if js.Truth(values["mainAlias"]) {
		m.Lines = append(m.Lines, MigratedLine{ID: nextID(), Alias: values["mainAlias"], GUID: values["mainGuid"], Label: "Cable", Kind: "wired", Weight: 1})
	}
	if js.Truth(values["secondAlias"]) {
		label := values["secondLabel"]
		if !js.Truth(label) {
			label = "Second connection"
		}
		if text, ok := label.(string); ok && text == "Cable" && len(m.Lines) > 0 {
			label = "Cable 2"
		}
		m.Lines = append(m.Lines, MigratedLine{ID: nextID(), Alias: values["secondAlias"], GUID: values["secondGuid"], Label: label, Kind: values["secondKind"], Metered: values["secondKind"] == "phone", Weight: 1})
	}
	if paths, ok := values["cableApps"].([]any); ok && js.Truth(values["mainAlias"]) {
		for _, p := range paths {
			m.AppLines.Set(js.String(p), m.Lines[0].ID)
		}
	}
	if paths, ok := values["secondApps"].([]any); ok {
		for _, p := range paths {
			s, ok := p.(string)
			if !ok {
				continue
			}
			if js.Truth(values["secondAlias"]) {
				m.AppLines.Set(s, m.Lines[len(m.Lines)-1].ID)
			} else {
				m.WaitingApps = append(m.WaitingApps, s)
			}
		}
	}
	return m
}
func PlaceWaitingApps(waiting []any, pins apps.Pins, id string) apps.Pins {
	if len(waiting) == 0 {
		return nil
	}
	result := append(apps.Pins{}, pins...)
	taken := map[string]bool{}
	for _, pin := range pins {
		taken[js.Lower(pin.Path)] = true
	}
	for _, p := range waiting {
		if s, ok := p.(string); ok && !taken[js.Lower(s)] {
			result.Set(s, id)
		}
	}
	return result
}

type Share struct {
	ID    string
	Value float64
}

type Shares []Share

func (shares Shares) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, share := range shares {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(js.MarshalString(share.ID))
		b.WriteByte(':')
		value, err := js.Marshal(share.Value)
		if err != nil {
			return nil, err
		}
		b.Write(value)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func LineForPort(port float64, shares []Share) string {
	position := math.Mod(port*0.6180339887498949, 1)
	edge := 0.0
	for _, share := range shares {
		edge += share.Value
		if position < edge {
			return share.ID
		}
	}
	return shares[len(shares)-1].ID
}
func AssignPorts(shares []Share) map[string][]int {
	result := map[string][]int{}
	for _, s := range shares {
		result[s.ID] = []int{}
	}
	if len(shares) == 0 {
		return result
	}
	for p := 1024; p <= 65535; p++ {
		id := LineForPort(float64(p), shares)
		result[id] = append(result[id], p)
	}
	return result
}
