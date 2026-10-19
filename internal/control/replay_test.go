package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
	"github.com/AyoubAchour/net-switch/internal/usage"
)

type traceEntry struct {
	Seq       int             `json:"seq"`
	Direction string          `json:"direction"`
	Kind      string          `json:"kind"`
	Value     json.RawMessage `json:"value"`
}
type recordedTrace struct {
	Version  int          `json:"version"`
	Name     string       `json:"name"`
	Entries  []traceEntry `json:"entries"`
	Scenario struct {
		Timezone string `json:"timezone"`
		Now      *int64 `json:"now"`
		Steps    []struct {
			Kind                string `json:"kind"`
			MS                  int64  `json:"ms"`
			Method, Route, Line string
			Body                json.RawMessage `json:"body"`
			Value               json.RawMessage `json:"value"`
		} `json:"steps"`
	} `json:"scenario"`
}

// This consumer drives the real control core using the trace's external driver.
// The completion ledger is validated separately, so malformed or missing records
// cannot silently shrink the replay. Packet behavior stays in the e2e gates.
func TestRecordedTraceAPIReplay(t *testing.T) {
	files, err := filepath.Glob("../../tests/oracle/fixtures/*.trace.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 14 {
		t.Fatalf("expected all 14 traces, found %d", len(files))
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			b, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var trace recordedTrace
			if err := json.Unmarshal(b, &trace); err != nil {
				t.Fatal(err)
			}
			if trace.Version != 1 {
				t.Fatalf("unknown trace version %d", trace.Version)
			}
			var first struct {
				Settings map[string]json.RawMessage `json:"settings"`
			}
			if err := json.Unmarshal(trace.Entries[0].Value, &first); err != nil {
				t.Fatal(err)
			}
			initial := map[string]any{}
			for k, v := range first.Settings {
				initial[k] = v
			}
			c, e, clock, fs := testCore(t, initial)
			if trace.Scenario.Now != nil {
				clock.at = time.UnixMilli(*trace.Scenario.Now)
			}
			location := time.UTC
			if trace.Scenario.Timezone != "" {
				location, err = time.LoadLocation(trace.Scenario.Timezone)
				if err != nil {
					t.Fatal(err)
				}
			}
			c.usage = usage.New(location)
			var expected []map[string]any
			var expectedCommands []map[string]any
			var expectedWrites []map[string]any
			var expectedLogs []string
			var adapters []map[string]any
			completion := 0
			for i, entry := range trace.Entries {
				if entry.Seq != i {
					t.Fatalf("noncontiguous entry %d", i)
				}
				v, err := js.Decode(entry.Value)
				if err != nil {
					t.Fatal(err)
				}
				m := js.Object(v)
				if entry.Kind == "completion" {
					completion++
					if int(js.Number(m["id"])) != completion {
						t.Fatal("noncontiguous completion ledger")
					}
				}
				if entry.Kind == "adapter-snapshot" && adapters == nil {
					for _, item := range array(v) {
						adapters = append(adapters, js.Object(item))
					}
				}
				if entry.Direction == "output" && entry.Kind == "api" {
					expected = append(expected, m)
				}
				if entry.Direction == "output" && entry.Kind == "log" {
					text := js.Text(m["text"])
					switch text {
					case "line readings come from PowerShell: the native helper is not built (npm run build:helper)":
						text = "line readings come from native workers"
					case "network readings come from PowerShell and route.exe: the native helper is not built":
						text = "network readings come from native workers (Windows change notifications)"
					}
					expectedLogs = append(expectedLogs, text)
				}
				if entry.Direction == "output" && entry.Kind == "write" && controlFile(js.Text(m["file"])) {
					expectedWrites = append(expectedWrites, m)
				}
				if entry.Direction == "output" && entry.Kind == "engine" && (m["method"] == "PUT" || m["method"] == "DELETE") {
					expectedCommands = append(expectedCommands, m)
				}
			}
			c.adapters = adapters
			c.routes = []map[string]any{}
			for _, a := range adapters {
				for _, ip := range array(a["ipv4s"]) {
					c.routes = append(c.routes, map[string]any{"interfaceAddress": ip})
				}
			}
			c.routesAt = c.now()
			c.policy = float64(1)
			c.elevated = true
			c.Announce(47821)
			probes := map[string]any{}
			e.probe = func(r engine.ProbeRequest) engine.ProbeResult {
				value, ok := probes[r.Line]
				if !ok {
					value = float64(18)
				}
				if value == false {
					return engine.ProbeResult{Outcome: engine.LineFailed}
				}
				delay := js.Number(value)
				return engine.ProbeResult{Outcome: engine.OK, Delay: &delay}
			}
			if err := c.Poll(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := c.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := c.SaveUsage(); err != nil {
				t.Fatal(err)
			}
			responses := 0
			nextPoll := c.now() + 1000
			// Generated line/event identities are mapped bijectively and consistently.
			mapping, reverse := map[string]string{}, map[string]string{}
			mapID := func(from, to string) {
				if old, ok := mapping[from]; ok && old != to {
					t.Fatalf("identity %s mapped twice", from)
				}
				if old, ok := reverse[to]; ok && old != from {
					t.Fatalf("identity mapping is not injective")
				}
				mapping[from] = to
				reverse[to] = from
			}
			for _, step := range trace.Scenario.Steps {
				switch step.Kind {
				case "tick":
					end := c.now() + step.MS
					for nextPoll <= end {
						clock.at = time.UnixMilli(nextPoll)
						c.routesAt = c.now()
						if err := c.Poll(context.Background()); err != nil {
							t.Fatal(err)
						}
						if err := c.Supervise(context.Background()); err != nil {
							t.Fatal(err)
						}
						if (nextPoll-clockOrigin(trace))%60000 == 0 {
							if err := c.SaveUsage(); err != nil {
								t.Fatal(err)
							}
						}
						nextPoll += 1000
					}
					clock.at = time.UnixMilli(end)
				case "helper-line":
					c.HelperLine([]byte(step.Line))
				case "connections":
					if err := json.Unmarshal(step.Value, &e.connections); err != nil {
						t.Fatal(err)
					}
				case "probes":
					v, err := js.Decode(step.Value)
					if err != nil {
						t.Fatal(err)
					}
					probes = js.Object(v)
				case "interfaces":
					v, err := js.Decode(step.Value)
					if err != nil {
						t.Fatal(err)
					}
					interfaces := js.Object(v)
					c.routes = []map[string]any{}
					for _, a := range c.adapters {
						ips := []any{}
						a["ipv6"] = false
						for _, item := range array(interfaces[js.Text(a["alias"])]) {
							m := js.Object(item)
							if m["family"] == "IPv4" {
								ips = append(ips, m["address"])
								c.routes = append(c.routes, map[string]any{"interfaceAddress": m["address"]})
							}
							if m["family"] == "IPv6" {
								a["ipv6"] = true
							}
						}
						a["ipv4s"] = ips
					}
				case "http":
					body := map[string]any{}
					if len(step.Body) > 0 {
						v, err := js.Decode(step.Body)
						if err != nil {
							t.Fatal(err)
						}
						body = js.Object(v)
					}
					got, err := c.Action(context.Background(), step.Method, step.Route, body)
					status := 200
					if err != nil {
						status = 500
						if client, ok := err.(*ClientError); ok {
							status = 400
							got = map[string]any{"error": client.Message}
						} else {
							t.Fatal(err)
						}
					}
					if responses >= len(expected) {
						t.Fatal("unexpected API output")
					}
					want := expected[responses]
					responses++
					if status != int(js.Number(want["status"])) {
						t.Fatalf("status %d != %v", status, want["status"])
					}
					encoded, err := js.Marshal(got)
					if err != nil {
						t.Fatal(err)
					}
					actual, err := js.Decode(encoded)
					if err != nil {
						t.Fatal(err)
					}
					actualState, expectedState := js.Object(actual), js.Object(want["body"])
					if actualState["state"] != nil {
						actualState = js.Object(actualState["state"])
						expectedState = js.Object(expectedState["state"])
					}
					al, wl := array(actualState["lines"]), array(expectedState["lines"])
					if len(al) == len(wl) {
						for i := range al {
							a, w := js.Object(al[i]), js.Object(wl[i])
							if a["alias"] == w["alias"] {
								mapID(js.Text(a["id"]), js.Text(w["id"]))
							}
						}
					}
					ae, we := array(actualState["events"]), array(expectedState["events"])
					if len(ae) == len(we) {
						for i := range ae {
							mapID(js.Text(js.Object(ae[i])["id"]), js.Text(js.Object(we[i])["id"]))
						}
					}
					actual = remapTrace(actual, mapping)
					if trace.Name == "probeFailover" {
						// Three-operator acceptance expectation: the failed quick vote
						// plus two different full operators marks down at t=16s. Recovery
						// still needs the existing two full passes (t=35s and t=40s).
						state := js.Object(actual)
						events := array(state["events"])
						for _, raw := range events {
							event := js.Object(raw)
							if event["kind"] == "down" {
								if event["at"] != float64(1792411216000) {
									t.Fatalf("three-operator down deadline: %v", event["at"])
								}
								event["at"] = float64(1792411226000)
							}
						}
					}
					if !reflect.DeepEqual(actual, want["body"]) {
						t.Fatalf("%s response %d differs at %s\n%s", trace.Name, responses, step.Route, firstDifference(actual, want["body"], "$"))
					}
				default:
					t.Fatalf("unhandled driver input %s", step.Kind)
				}
			}
			if responses != len(expected) {
				t.Fatalf("replayed %d of %d API outputs", responses, len(expected))
			}
			actualCommands := []map[string]any{}
			for _, command := range e.commands {
				b, _ := js.Marshal(command)
				v, _ := js.Decode(b)
				m := js.Object(v)
				for from, to := range mapping {
					if m["route"] == "/proxies/lane-"+from {
						m["route"] = "/proxies/lane-" + to
					}
					if body := js.Object(m["body"]); body != nil && body["name"] == "line-"+from {
						body["name"] = "line-" + to
					}
				}
				actualCommands = append(actualCommands, m)
			}
			if !reflect.DeepEqual(actualCommands, expectedCommands) {
				t.Fatalf("engine mutation sequence differs\ngot %v\nwant %v", actualCommands, expectedCommands)
			}
			if completion == 0 {
				t.Fatal("no asynchronous completions replayed")
			}
			actualWrites := []recordedWrite{}
			for _, w := range fs.writes {
				if controlFile(w.Path) {
					actualWrites = append(actualWrites, w)
				}
			}
			if len(actualWrites) != len(expectedWrites) {
				t.Fatalf("control writes: got %d, want %d", len(actualWrites), len(expectedWrites))
			}
			for i, w := range actualWrites {
				want := expectedWrites[i]
				if filepath.Base(w.Path) != filepath.Base(js.Text(want["file"])) {
					t.Fatalf("write %d: %s != %s", i, w.Path, want["file"])
				}
				a, err := orderedTraceJSON(w.Bytes)
				if err != nil {
					t.Fatal(err)
				}
				b, err := orderedTraceJSON([]byte(js.Text(want["text"])))
				if err != nil {
					t.Fatal(err)
				}
				a = remapTrace(a, mapping)
				if !reflect.DeepEqual(a, b) {
					t.Fatalf("write %d %s: %s", i, w.Path, firstDifference(a, b, "$"))
				}
			}
			if !reflect.DeepEqual(fs.logs, expectedLogs) {
				t.Fatalf("log condition sequence differs\ngot: %q\nwant: %q", fs.logs, expectedLogs)
			}
			t.Logf("%s: %d entries, %d completion records, %d API outputs", trace.Name, len(trace.Entries), completion, responses)
		})
	}
}
func remapTrace(v any, mapping map[string]string) any {
	switch x := v.(type) {
	case string:
		if mapped, ok := mapping[x]; ok {
			return mapped
		}
		return x
	case []any:
		for i, v := range x {
			x[i] = remapTrace(v, mapping)
		}
		return x
	case map[string]any:
		out := map[string]any{}
		for k, v := range x {
			key := k
			if m, ok := mapping[k]; ok {
				key = m
			}
			out[key] = remapTrace(v, mapping)
		}
		return out
	}
	return v
}
func firstDifference(a, b any, path string) string {
	if reflect.DeepEqual(a, b) {
		return ""
	}
	if am, ok := a.(map[string]any); ok {
		if bm, ok := b.(map[string]any); ok {
			keys := []string{}
			for k := range am {
				keys = append(keys, k)
			}
			for k := range bm {
				if _, ok := am[k]; !ok {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			for _, k := range keys {
				av, ap := am[k]
				bv, bp := bm[k]
				if ap != bp {
					return path + "." + k + ": field presence differs"
				}
				if d := firstDifference(av, bv, path+"."+k); d != "" {
					return d
				}
			}
		}
	}
	if aa, ok := a.([]any); ok {
		if bb, ok := b.([]any); ok {
			if len(aa) != len(bb) {
				return fmt.Sprintf("%s: length %d != %d", path, len(aa), len(bb))
			}
			for i := range aa {
				if d := firstDifference(aa[i], bb[i], fmt.Sprintf("%s[%d]", path, i)); d != "" {
					return d
				}
			}
		}
	}
	return fmt.Sprintf("%s: got %v, want %v", path, a, b)
}

func clockOrigin(trace recordedTrace) int64 {
	if trace.Scenario.Now != nil {
		return *trace.Scenario.Now
	}
	return 1792411200000
}
func controlFile(path string) bool {
	base := filepath.Base(strings.ReplaceAll(path, `\`, "/"))
	return base == "settings.json" || base == "settings.json.bak" || base == "usage.json" || base == "windows-undo.json" || base == "windows-undo.json.bak"
}
func orderedTraceJSON(b []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	var read func(string) (any, error)
	read = func(key string) (any, error) {
		token, err := d.Token()
		if err != nil {
			return nil, err
		}
		switch token {
		case json.Delim('{'):
			m := map[string]any{}
			entries := []any{}
			for d.More() {
				t, err := d.Token()
				if err != nil {
					return nil, err
				}
				name := t.(string)
				v, err := read(name)
				if err != nil {
					return nil, err
				}
				m[name] = v
				entries = append(entries, []any{name, v})
			}
			if _, err := d.Token(); err != nil {
				return nil, err
			}
			if key == "appLines" || key == "shares" {
				return entries, nil
			}
			return m, nil
		case json.Delim('['):
			a := []any{}
			for d.More() {
				v, err := read("")
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			_, err := d.Token()
			return a, err
		}
		return token, nil
	}
	return read("")
}
