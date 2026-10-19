package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/singbox"
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
func TestRecordedTraceReplay(t *testing.T) {
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
			var expectedRequests []map[string]any
			var expectedReads []string
			var expectedWrites []map[string]any
			var expectedEngineWrites []map[string]any
			var expectedLogs []string
			var expectedRemoves []string
			var expectedSpawns []any
			var expectedOutside []any
			var expectedConsole string
			var expectedEvents []any
			var adapters []map[string]any
			completion := 0
			e.replies = []recordedReply{}
			for i, entry := range trace.Entries {
				if entry.Seq != i {
					t.Fatalf("noncontiguous entry %d", i)
				}
				if err := knownTraceEntry(entry); err != nil {
					t.Fatal(err)
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
					if i == 0 || trace.Entries[i-1].Direction != "input" || trace.Entries[i-1].Kind != js.Text(m["kind"]) {
						t.Fatalf("completion %d is detached from its boundary", completion)
					}
				}
				if entry.Direction == "input" && entry.Kind == "engine-reply" {
					e.replies = append(e.replies, recordedReply{Route: js.Text(m["route"]), Status: int(js.Number(m["status"])), Body: m["body"]})
				}
				if entry.Kind == "adapter-snapshot" && adapters == nil {
					for _, item := range array(v) {
						adapters = append(adapters, js.Object(item))
					}
				}
				if entry.Direction == "output" && entry.Kind == "api" {
					expected = append(expected, m)
				}
				if entry.Direction == "output" && entry.Kind == "event" {
					expectedEvents = append(expectedEvents, m)
				}
				if entry.Direction == "output" {
					switch entry.Kind {
					case "remove":
						expectedRemoves = append(expectedRemoves, js.Text(m["file"]))
					case "spawn":
						expectedSpawns = append(expectedSpawns, m)
					case "outside-close":
						expectedOutside = append(expectedOutside, m["items"])
					case "console":
						expectedConsole = js.Text(m["text"])
					}
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
				if entry.Direction == "output" && entry.Kind == "write" && engineFile(js.Text(m["file"])) {
					expectedEngineWrites = append(expectedEngineWrites, m)
				}
				if entry.Direction == "output" && entry.Kind == "engine" && (m["method"] == "PUT" || m["method"] == "DELETE") {
					expectedCommands = append(expectedCommands, m)
				}
				if entry.Direction == "output" && entry.Kind == "engine" && m["method"] == "GET" && !strings.HasSuffix(js.Text(m["route"]), "/delay") {
					expectedReads = append(expectedReads, js.Text(m["route"]))
				}
				if entry.Direction == "output" && entry.Kind == "engine" && !strings.HasSuffix(js.Text(m["route"]), "/delay") {
					expectedRequests = append(expectedRequests, m)
				}
			}
			if trace.Name == "probeFailover" {
				// Three-operator checks advance the failure from tick 26 to 16.
				// This named expectation moves only its transition and reply.
				const from, to = 28, 18
				if len(expectedRequests) <= from || expectedRequests[from]["route"] != "/proxies/lane-a1" || js.Object(expectedRequests[from]["body"])["name"] != "line-b2" {
					t.Fatal("probe timing expectation no longer matches frozen trace")
				}
				request := expectedRequests[from]
				copy(expectedRequests[to+1:from+1], expectedRequests[to:from])
				expectedRequests[to] = request
				reply := e.replies[from]
				copy(e.replies[to+1:from+1], e.replies[to:from])
				e.replies[to] = reply
			}
			e.resourceIDs = map[string]string{}
			for _, response := range expected {
				state := js.Object(response["body"])
				if state["state"] != nil {
					state = js.Object(state["state"])
				}
				if list := array(state["lines"]); len(list) > 0 {
					for _, line := range c.itemsLocked() {
						for _, raw := range list {
							item := js.Object(raw)
							if item["alias"] == line.Alias {
								e.resourceIDs[line.ID] = js.Text(item["id"])
								break
							}
						}
					}
					break
				}
			}
			installReplayAdapter(t, c, e, clock, fs)
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
			if err := c.ApplyPolicy(context.Background()); err != nil {
				t.Fatal(err)
			}
			consoleMessage, err := c.PublishSession(47821, strings.Repeat("ab", 24), 123)
			if err != nil {
				t.Fatal(err)
			}
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
			for _, w := range expectedWrites {
				if filepath.Base(js.Text(w["file"])) == "server.json" {
					v, _ := js.Decode([]byte(js.Text(w["text"])))
					mapID(strings.Repeat("ab", 24), js.Text(js.Object(v)["token"]))
				}
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
					e.wireConnections = append(json.RawMessage{}, step.Value...)
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
			if len(e.requests) != len(expectedRequests) {
				t.Fatalf("engine request count differs")
			}
			for i, r := range e.requests {
				b, _ := js.Marshal(r)
				normalized, err := rewriteTraceStrings(b, func(s string) string { return normalizeResourceString(s, mapping) })
				if err != nil {
					t.Fatal(err)
				}
				v, _ := js.Decode(normalized)
				if !reflect.DeepEqual(v, expectedRequests[i]) {
					t.Fatalf("engine request %d differs: %s", i, firstDifference(v, expectedRequests[i], "$"))
				}
			}
			reads := []string{}
			for _, r := range e.requests {
				if r["method"] == "GET" {
					reads = append(reads, js.Text(r["route"]))
				}
			}
			if !equalStringLists(reads, expectedReads) {
				t.Fatalf("engine read request sequence differs: %v != %v", reads, expectedReads)
			}
			if completion == 0 {
				t.Fatal("no asynchronous completions replayed")
			}
			if len(e.replies) != 0 {
				t.Fatalf("%d unconsumed engine completions", len(e.replies))
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
			if len(fs.events) != len(expectedEvents) {
				t.Fatalf("event count differs: %d != %d", len(fs.events), len(expectedEvents))
			}
			for i, event := range fs.events {
				mapID(js.Text(js.Object(event)["id"]), js.Text(js.Object(expectedEvents[i])["id"]))
				v := remapTrace(event, mapping)
				if trace.Name == "probeFailover" && js.Object(v)["kind"] == "down" {
					if js.Object(v)["at"] != float64(1792411216000) {
						t.Fatal("unexpected full-check failure deadline")
					}
					js.Object(v)["at"] = float64(1792411226000)
				}
				if !reflect.DeepEqual(v, expectedEvents[i]) {
					t.Fatalf("event %d differs: %s", i, firstDifference(v, expectedEvents[i], "$"))
				}
			}
			removes := []string{}
			for _, p := range fs.removes {
				removes = append(removes, normalizeResourceString(p, mapping))
			}
			if len(removes) != len(expectedRemoves) || !equalStringLists(removes, expectedRemoves) {
				t.Fatalf("remove sequence differs: %v != %v", removes, expectedRemoves)
			}
			if len(fs.spawns) != len(expectedSpawns) {
				t.Fatalf("spawn count differs: %d != %d", len(fs.spawns), len(expectedSpawns))
			}
			for i, s := range fs.spawns {
				b, _ := js.Marshal(s)
				normalized, err := rewriteTraceStrings(b, func(s string) string { return normalizeResourceString(s, mapping) })
				if err != nil {
					t.Fatal(err)
				}
				v, _ := js.Decode(normalized)
				if !reflect.DeepEqual(v, expectedSpawns[i]) {
					t.Fatalf("spawn differs: %s", firstDifference(v, expectedSpawns[i], "$"))
				}
			}
			if len(fs.outsideCloses) != len(expectedOutside) {
				t.Fatalf("outside close count differs")
			}
			for i, v := range fs.outsideCloses {
				if !reflect.DeepEqual(v, expectedOutside[i]) {
					t.Fatalf("outside selectors differ: %s", firstDifference(v, expectedOutside[i], "$"))
				}
			}
			for from, to := range mapping {
				consoleMessage = strings.ReplaceAll(consoleMessage, from, to)
			}
			if consoleMessage != expectedConsole {
				t.Fatalf("console announcement differs: %s != %s", consoleMessage, expectedConsole)
			}
			engineWrites := []recordedWrite{}
			for _, w := range fs.writes {
				if engineFile(w.Path) {
					engineWrites = append(engineWrites, w)
				}
			}
			if len(engineWrites) != len(expectedEngineWrites) {
				t.Fatalf("engine writes: got %d, want %d", len(engineWrites), len(expectedEngineWrites))
			}
			for i, w := range engineWrites {
				want := expectedEngineWrites[i]
				name := normalizeResourceString(filepath.Base(w.Path), mapping)
				if name != filepath.Base(js.Text(want["file"])) {
					t.Fatalf("engine write %d: %s != %s", i, name, want["file"])
				}
				if name == "engine-config.json" {
					a, _ := js.Decode(w.Bytes)
					b, _ := js.Decode([]byte(js.Text(want["text"])))
					secret := func(v any) string {
						return js.Text(js.Object(js.Object(js.Object(v)["experimental"])["clash_api"])["secret"])
					}
					mapID(secret(a), secret(b))
				}
				normalized, err := rewriteTraceStrings(w.Bytes, func(s string) string { return normalizeResourceString(s, mapping) })
				if err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(normalized)
				if hex.EncodeToString(sum[:]) != want["sha256"] {
					t.Fatalf("engine write %d %s SHA-256 differs: %x != %s\n%s", i, name, sum, want["sha256"], normalized)
				}
			}
			t.Logf("%s: %d entries, %d completion records, %d API outputs", trace.Name, len(trace.Entries), completion, responses)
		})
	}
}

func knownTraceEntry(e traceEntry) error {
	allowed := ""
	switch e.Direction {
	case "input":
		allowed = " initial-files http helper-line interfaces connections probes adapter-snapshot counter-sample engine-reply probe-result clock-tick file-completion completion async-result socket-completion process-exit timer-completion "
	case "output":
		allowed = " api event engine spawn write remove outside-close log console exit "
	default:
		return fmt.Errorf("unknown trace direction %q", e.Direction)
	}
	if !strings.Contains(allowed, " "+e.Kind+" ") {
		return fmt.Errorf("unhandled %s trace kind %q", e.Direction, e.Kind)
	}
	return nil
}

type replayChild struct {
	closed chan struct{}
	once   sync.Once
}

func (*replayChild) PID() int          { return 456 }
func (*replayChild) Stdout() io.Reader { return strings.NewReader("") }
func (*replayChild) Stderr() io.Reader { return strings.NewReader("") }
func (p *replayChild) Wait() error     { <-p.closed; return nil }
func (p *replayChild) Kill() error     { p.once.Do(func() { close(p.closed) }); return nil }

type replayTransport func(*http.Request) (*http.Response, error)

func (f replayTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func installReplayAdapter(t *testing.T, c *Core, e *fakeEngine, clock *fakeClock, files *memoryFiles) {
	t.Helper()
	client := &http.Client{Transport: replayTransport(func(r *http.Request) (*http.Response, error) {
		var body any
		if r.Body != nil {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			if len(b) > 0 {
				body, err = js.Decode(b)
				if err != nil {
					return nil, err
				}
			}
		}
		if r.Method == "PUT" || r.Method == "DELETE" {
			command := map[string]any{"route": r.URL.Path, "method": r.Method}
			if body != nil {
				command["body"] = body
			}
			e.commands = append(e.commands, command)
		}
		request := map[string]any{"route": r.URL.Path, "method": r.Method}
		if body != nil {
			request["body"] = body
		}
		e.requests = append(e.requests, request)
		route := r.URL.Path
		if strings.HasPrefix(route, "/proxies/lane-") {
			id := strings.TrimPrefix(route, "/proxies/lane-")
			if mapped, ok := e.resourceIDs[id]; ok {
				route = "/proxies/lane-" + mapped
			}
		}
		if len(e.replies) == 0 {
			return nil, fmt.Errorf("unrecorded engine request %s %s", r.Method, r.URL.Path)
		}
		reply := e.replies[0]
		if reply.Route != route {
			return nil, fmt.Errorf("completion order: got %s, recorded %s", route, reply.Route)
		}
		e.replies = e.replies[1:]
		response, err := js.Marshal(reply.Body)
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: reply.Status, Body: io.NopCloser(bytes.NewReader(response)), Header: http.Header{}, Request: r}, nil
	})}
	c.op.Platform.(*fakePlatform).probe = func(a map[string]any) (any, error) {
		return e.probe(engine.ProbeRequest{OperationID: js.Text(a["opId"]), Line: js.Text(a["line"]), Index: uint32(js.Number(a["index"])), Target: js.Text(a["target"]), Quick: a["quick"] == true}), nil
	}
	e.real = singbox.New(singbox.Options{Executable: "/test/engine/sing-box.exe", DataDir: "/test", Mode: "tun", Platform: c.op.Platform, HTTP: client, Files: c.op.IO, Now: clock.Now, Sleep: func(context.Context, time.Duration) error { return nil }, FreePort: func() (int, error) { return 49000, nil }, ID: c.op.ID, Verify: func() error { return nil }, StartProcess: func(exe, config, dir string) (singbox.Child, error) {
		files.spawns = append(files.spawns, map[string]any{"exe": exe, "args": []string{"run", "-c", config, "--disable-color"}})
		return &replayChild{closed: make(chan struct{})}, nil
	}, ListFiles: func(dir string) ([]string, error) {
		files.mu.Lock()
		defer files.mu.Unlock()
		names := []string{}
		for path := range files.data {
			if filepath.Dir(path) == filepath.Clean(dir) {
				names = append(names, filepath.Base(path))
			}
		}
		sort.Strings(names)
		return names, nil
	}})
	t.Cleanup(func() {
		if err := e.real.Stop(context.Background()); err != nil {
			t.Error(err)
		}
	})
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
func engineFile(path string) bool {
	base := filepath.Base(strings.ReplaceAll(path, `\`, "/"))
	return base == "engine-config.json" || base == "engine.pid" || strings.HasPrefix(base, "apps-") || strings.HasPrefix(base, "share-") || strings.HasPrefix(base, "cut-")
}
func normalizeResourceString(s string, mapping map[string]string) string {
	if strings.HasPrefix(s, "/proxies/lane-") {
		id := strings.TrimPrefix(s, "/proxies/lane-")
		if v, ok := mapping[id]; ok {
			return "/proxies/lane-" + v
		}
	}
	if v, ok := mapping[s]; ok {
		return v
	}
	for from, to := range mapping {
		for _, prefix := range []string{"line-", "lane-", "apps-", "share-", "cut-"} {
			if s == prefix+from {
				return prefix + to
			}
			if s == prefix+from+".json" {
				return prefix + to + ".json"
			}
		}
	}
	resource := strings.ReplaceAll(s, `\`, "/")
	if resource == "/test/engine/sing-box.exe" {
		return "/oracle/engine/sing-box.exe"
	}
	if strings.HasPrefix(resource, "/test/") {
		return "/oracle/data/" + normalizeResourceString(strings.TrimPrefix(resource, "/test/"), mapping)
	}
	return s
}
func equalStringLists(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func rewriteTraceStrings(b []byte, convert func(string) string) ([]byte, error) {
	out := []byte{}
	for i := 0; i < len(b); {
		if b[i] != '"' {
			out = append(out, b[i])
			i++
			continue
		}
		end := i + 1
		for end < len(b) {
			if b[end] == '\\' {
				end += 2
				continue
			}
			if b[end] == '"' {
				break
			}
			end++
		}
		if end >= len(b) {
			return nil, fmt.Errorf("unterminated JSON string")
		}
		var text string
		if err := json.Unmarshal(b[i:end+1], &text); err != nil {
			return nil, err
		}
		next := convert(text)
		if next == text {
			out = append(out, b[i:end+1]...)
		} else {
			out = append(out, js.MarshalString(next)...)
		}
		i = end + 1
	}
	return out, nil
}
func controlFile(path string) bool {
	base := filepath.Base(strings.ReplaceAll(path, `\`, "/"))
	return base == "server.json" || base == "settings.json" || base == "settings.json.bak" || base == "usage.json" || base == "windows-undo.json" || base == "windows-undo.json.bak"
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
