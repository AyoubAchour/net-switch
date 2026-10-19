//go:build linux

// Package suite is the Linux acceptance suite: cases that judge an engine
// only by what apps and servers see on the namespace network, plus what the
// engine reports through the driver. Each case builds the network fresh,
// plays the control service through engine.Driver, and tears everything
// down. Labels and what they mean are in package harness.
package suite

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/app"
	"github.com/AyoubAchour/net-switch/tests/linux/engine"
	"github.com/AyoubAchour/net-switch/tests/linux/harness"
	"github.com/AyoubAchour/net-switch/tests/linux/topo"
	"github.com/AyoubAchour/net-switch/tests/linux/wire"
)

// AppsDir holds the test apps: copies of the harness binary, one per app.
const AppsDir = "/opt/nsapps"

// The test apps. alpha is never pinned; bravo is pinned to line b and charlie
// to line c by default; the rest are free for cases to use (the overload
// cases need many apps at once).
var AppNames = []string{"alpha", "bravo", "charlie", "delta", "foxtrot", "golf", "hotel", "india", "juliett", "kilo"}

// AppPath is where an app's program is.
func AppPath(name string) string { return filepath.Join(AppsDir, name, "nsapp") }

// Users are the accounts apps run as.
type Users struct {
	UID, GID           int // the desktop user
	OtherUID, OtherGID int // a second user, for cross-user cases
}

// Config is what the suite needs from the run.
type Config struct {
	Self   string // this program, for "serve" and "exec"
	Driver engine.Driver
	Users  Users
	// Fixtures are filled in by Provision before the identity cases run.
	Fixtures *Fixtures
	// CgroupRoot is the cgroup v2 folder delegated to the harness; cases
	// create their scopes in it.
	CgroupRoot string
	// QUIC is the QUIC fixture (tests/quicfixture) installed as an app, at
	// QUICApp; "" when the run has none.
	QUIC string
}

// Env is one running case's world.
type Env struct {
	T      *harness.T
	Net    *topo.Net
	Eng    engine.Driver
	cfg    Config
	engCfg engine.Config
	// Before is the PC's routing state before the engine first started.
	Before topo.Snapshot
	sharedDir string // SharedDir, once made
}

type caseFunc func(e *Env)

type registry struct {
	cfg   Config
	cases []*harness.Case
}

func (r *registry) add(id, title string, label harness.Label, spec string, timeout time.Duration, fn caseFunc) {
	r.cases = append(r.cases, &harness.Case{
		ID: id, Title: title, Label: label, Spec: spec, Timeout: timeout,
		Run: func(t *harness.T) { fn(r.setup(t)) },
	})
}

// defect adds a baseline-defect case: defect names the known baseline defect
// its one Expect assertion checks for.
func (r *registry) defect(id, title, defect, spec string, timeout time.Duration, fn caseFunc) {
	r.add(id, title, harness.BaselineDefect, spec, timeout, fn)
	r.cases[len(r.cases)-1].Defect = defect
}

// pending adds a gate the suite can't check yet: waits says what it needs.
// It never runs; on 1.0 it fails the run until it's written.
func (r *registry) pending(id, title, spec, waits string) {
	r.cases = append(r.cases, &harness.Case{ID: id, Title: title, Label: harness.Pending, Spec: spec, Waits: waits})
}

// Each file of cases registers itself, with its place in the run order.
var groups []struct {
	order int
	add   func(*registry)
}

func register(order int, add func(*registry)) {
	groups = append(groups, struct {
		order int
		add   func(*registry)
	}{order, add})
}

// Cases is every case, in run order.
func Cases(cfg Config) []*harness.Case {
	r := &registry{cfg: cfg}
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].order < groups[j].order })
	for _, g := range groups {
		g.add(r)
	}
	return r.cases
}

func (r *registry) setup(t *harness.T) *Env {
	e := &Env{T: t, Eng: r.cfg.Driver, cfg: r.cfg}
	t.Cleanup(func() {
		ctx := t.Context()
		if e.Eng.Running() {
			err := e.Eng.Stop(ctx)
			t.Check(err == nil, "the engine stops cleanly after the case (%v)", err)
		}
		var health, down error
		if e.Net != nil {
			health = e.Net.Healthy()
			down = e.Net.Down(ctx)
		}
		if health != nil {
			t.Fatalf("the topology's servers didn't last the case: %v", health)
		}
		if down != nil {
			t.Fatalf("the network didn't come down cleanly: %v", down)
		}
		if left := topo.Leftovers(); len(left) > 0 {
			t.Fatalf("namespaces left after the case: %v", left)
		}
	})
	net, err := topo.Up(t.Context(), r.cfg.Self, t.Dir())
	e.Net = net
	if err != nil {
		t.Fatalf("network didn't come up: %v", err)
	}
	return e
}

// Ctx is the case's context.
func (e *Env) Ctx() context.Context { return e.T.Context() }

// Sleep waits, unless the case times out.
func (e *Env) Sleep(d time.Duration) {
	select {
	case <-time.After(d):
	case <-e.Ctx().Done():
	}
}

// App is a test app as the engine pins it.
func (e *Env) App(name string) engine.App { return engine.App{Path: AppPath(name)} }

// DefaultConfig is three lines, bravo pinned to b and charlie to c, no
// combining, no IPv6.
func (e *Env) DefaultConfig() engine.Config {
	return engine.Config{
		Lines: topo.EngineLines(),
		Policy: engine.Policy{Pins: []engine.Pin{
			{App: e.App("bravo"), Line: "b"},
			{App: e.App("charlie"), Line: "c"},
		}},
	}
}

// Snapshot reads the PC's routing state, or stops the case.
func (e *Env) Snapshot() topo.Snapshot {
	s, err := e.Net.Snapshot(e.Ctx())
	if err != nil {
		e.T.Fatalf("snapshot: %v", err)
	}
	return s
}

// StartEngine starts the engine (stopping the case if it can't) and stops it
// after the case.
func (e *Env) StartEngine(cfg engine.Config) {
	if e.Before == nil {
		e.Before = e.Snapshot()
		_ = e.Before.Write(filepath.Join(e.T.Dir(), "state-before.txt"))
	}
	e.engCfg = cfg
	env := engine.Env{Netns: topo.DUT, WorkDir: filepath.Join(e.T.Dir(), "engine"), Logf: e.T.Logf}
	start := time.Now()
	if err := e.Eng.Start(e.Ctx(), env, cfg); err != nil {
		e.T.Fatalf("engine didn't start: %v", err)
	}
	e.T.Logf("engine started in %s", time.Since(start).Round(time.Millisecond))
}

// StopEngine stops the engine, recording a failed stop as a check.
func (e *Env) StopEngine() bool {
	return e.T.Check(e.Eng.Stop(e.Ctx()) == nil, "the engine stops cleanly")
}

// Apply changes the policy, or stops the case.
func (e *Env) Apply(p engine.Policy) {
	if err := e.Eng.Apply(e.Ctx(), p); err != nil {
		e.T.Fatalf("apply policy: %v", err)
	}
	e.engCfg.Policy = p
}

// SetLanes points lanes, or stops the case.
func (e *Env) SetLanes(lanes map[engine.LineID]engine.LineID) {
	if err := e.Eng.SetLanes(e.Ctx(), lanes); err != nil {
		e.T.Fatalf("set lanes: %v", err)
	}
}

// Flows lists the engine's flows, or stops the case.
func (e *Env) Flows() []engine.Flow {
	flows, err := e.Eng.Flows(e.Ctx())
	if err != nil {
		e.T.Fatalf("flows: %v", err)
	}
	return flows
}

// User picks who an app runs as.
type User int

const (
	AsUser  User = iota // the desktop user
	AsOther             // the second user
	AsRoot
)

// Run describes starting a program on the fake PC.
type Run struct {
	App     string   // a test app's name, or
	Program string   // any program
	Args    []string // after the program; for apps, after "app"
	User    User
	Netns   string // default: the PC
	Cgroup  string
	Env     []string
	Timeout time.Duration // default 60 s
}

func (e *Env) command(ctx context.Context, r Run) *exec.Cmd {
	args := []string{"exec", "--netns", r.Netns}
	if r.Netns == "" {
		args[2] = topo.DUT
	}
	switch r.User {
	case AsUser:
		args = append(args, "--uid", strconv.Itoa(e.cfg.Users.UID), "--gid", strconv.Itoa(e.cfg.Users.GID))
	case AsOther:
		args = append(args, "--uid", strconv.Itoa(e.cfg.Users.OtherUID), "--gid", strconv.Itoa(e.cfg.Users.OtherGID))
	}
	if r.Cgroup != "" {
		args = append(args, "--cgroup", r.Cgroup)
	}
	for _, kv := range r.Env {
		args = append(args, "--env", kv)
	}
	args = append(args, "--")
	if r.App != "" {
		args = append(args, AppPath(r.App), "app")
	} else {
		args = append(args, r.Program)
	}
	args = append(args, r.Args...)
	cmd := exec.CommandContext(ctx, e.cfg.Self, args...)
	cmd.WaitDelay = 5 * time.Second
	return cmd
}

func (r Run) name() string {
	if r.App != "" {
		return r.App + " " + strings.Join(r.Args, " ")
	}
	return r.Program + " " + strings.Join(r.Args, " ")
}

// Exec runs a program to the end and returns its standard output. A program
// that can't run or exits with an error stops the case.
func (e *Env) Exec(r Run) []byte {
	out, err := e.TryExec(r)
	if err != nil {
		e.T.Fatalf("%v", err)
	}
	return out
}

// TryExec is Exec, returning the failure instead.
func (e *Env) TryExec(r Run) ([]byte, error) {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(e.Ctx(), timeout)
	defer cancel()
	cmd := e.command(ctx, r)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	e.logRun(r, stdout.Bytes(), stderr.Bytes())
	if err != nil {
		return stdout.Bytes(), fmt.Errorf("%s: %v: %s", r.name(), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func (e *Env) logRun(r Run, stdout, stderr []byte) {
	f, err := os.OpenFile(filepath.Join(e.T.Dir(), "apps.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s $ %s\n", time.Now().UTC().Format("15:04:05.000"), r.name())
	if len(stdout) > 0 {
		fmt.Fprintf(f, "  out: %s\n", truncate(stdout, 4000))
	}
	if len(stderr) > 0 {
		fmt.Fprintf(f, "  err: %s\n", truncate(stderr, 2000))
	}
}

func truncate(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// lastLine is a program's last non-empty output line: its JSON result (modes
// may print progress lines such as "ready ..." before it).
func lastLine(data []byte) []byte {
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	return bytes.TrimSpace(lines[len(lines)-1])
}

// RunJSON runs a program and decodes its JSON result into out.
func (e *Env) RunJSON(r Run, out any) {
	data := e.Exec(r)
	if err := json.Unmarshal(lastLine(data), out); err != nil {
		e.T.Fatalf("%s printed no JSON result: %v: %s", r.name(), err, truncate(data, 300))
	}
}

// lockedBuffer is a bytes.Buffer a program writes while the case reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buf.Bytes())
}

func (b *lockedBuffer) String() string { return string(b.Bytes()) }

// Bg is a program running in the background.
type Bg struct {
	r      Run
	cmd    *exec.Cmd
	stdout lockedBuffer
	stderr lockedBuffer
	done   chan struct{}
	err    error
	cancel context.CancelFunc
}

// Pid is the program's process id (the launcher execs it, so it's the app).
func (b *Bg) Pid() int { return b.cmd.Process.Pid }

// Start runs a program in the background; it's killed after the case.
func (e *Env) Start(r Run) *Bg {
	ctx, cancel := context.WithCancel(context.Background())
	b := &Bg{r: r, cmd: e.command(ctx, r), done: make(chan struct{}), cancel: cancel}
	b.cmd.Stdout, b.cmd.Stderr = &b.stdout, &b.stderr
	if err := b.cmd.Start(); err != nil {
		cancel()
		e.T.Fatalf("start %s: %v", r.name(), err)
	}
	go func() {
		b.err = b.cmd.Wait()
		close(b.done)
	}()
	e.T.Cleanup(func() {
		b.cancel()
		<-b.done
		e.logRun(r, b.stdout.Bytes(), b.stderr.Bytes())
	})
	return b
}

// Wait waits for the program and returns its output; a failure stops the case.
func (b *Bg) Wait(e *Env, timeout time.Duration) []byte {
	select {
	case <-b.done:
	case <-time.After(timeout):
		b.cancel()
		<-b.done
		e.T.Fatalf("%s didn't finish within %s", b.r.name(), timeout)
	case <-e.Ctx().Done():
		b.cancel()
		<-b.done
		e.T.Fatalf("%s: the case timed out", b.r.name())
	}
	if b.err != nil {
		e.T.Fatalf("%s: %v: %s", b.r.name(), b.err, strings.TrimSpace(b.stderr.String()))
	}
	return b.stdout.Bytes()
}

// WaitJSON waits and decodes the result.
func (b *Bg) WaitJSON(e *Env, timeout time.Duration, out any) {
	data := b.Wait(e, timeout)
	if err := json.Unmarshal(lastLine(data), out); err != nil {
		e.T.Fatalf("%s printed no JSON result: %v: %s", b.r.name(), err, truncate(data, 300))
	}
}

// WaitOutput waits until the program has printed want, or stops the case.
func (b *Bg) WaitOutput(e *Env, want string, timeout time.Duration) {
	b.WaitLine(e, want, timeout)
}

// WaitLine waits for a complete output line starting with prefix and returns
// it. A line still being written (no newline yet) doesn't count.
func (b *Bg) WaitLine(e *Env, prefix string, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	for {
		lines := strings.Split(b.stdout.String(), "\n")
		for _, line := range lines[:len(lines)-1] {
			if strings.HasPrefix(line, prefix) {
				return line
			}
		}
		select {
		case <-b.done:
			e.T.Fatalf("%s exited before printing %q: %v: %s", b.r.name(), prefix, b.err, strings.TrimSpace(b.stderr.String()))
		case <-time.After(20 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			e.T.Fatalf("%s didn't print %q within %s", b.r.name(), prefix, timeout)
		}
	}
}

// WaitHeld waits for what an app prints before it holds its sockets for a
// release barrier, decodes it into out, and checks the app is still holding.
// The line is "<label> {json}", or with label "" the JSON alone.
func (b *Bg) WaitHeld(e *Env, label string, timeout time.Duration, out any) {
	prefix := "{"
	if label != "" {
		prefix = label + " "
	}
	line := b.WaitLine(e, prefix, timeout)
	if label != "" {
		line = strings.TrimPrefix(line, prefix)
	}
	if err := json.Unmarshal([]byte(line), out); err != nil {
		e.T.Fatalf("%s printed no JSON result (%q): %v: %s", b.r.name(), label, err, truncate([]byte(line), 300))
	}
	if !b.Running() {
		e.T.Fatalf("%s exited instead of holding its sockets until released: %v: %s", b.r.name(), b.err, strings.TrimSpace(b.stderr.String()))
	}
}

// Release is a release barrier: a file the case creates when an app may let
// go of what it holds.
type Release string

// NewRelease makes a release barrier's path in the case's shared folder.
func (e *Env) NewRelease(name string) Release {
	return Release(filepath.Join(e.SharedDir(), "release-"+name))
}

// Arg is the barrier as an app's --release-file argument.
func (r Release) Arg() []string { return []string{"--release-file", string(r)} }

// Open lets the apps waiting on the barrier go.
func (r Release) Open(e *Env) {
	if err := os.WriteFile(string(r), nil, 0o644); err != nil {
		e.T.Fatalf("release %s: %v", r, err)
	}
}

// Running reports whether the program hasn't exited yet.
func (b *Bg) Running() bool {
	select {
	case <-b.done:
		return false
	default:
		return true
	}
}

// Stop ends a background program.
func (b *Bg) Stop() {
	b.cancel()
	<-b.done
}

// --- traffic helpers ----------------------------------------------------

// To is a server address with a port.
func To(addr netip.Addr, port uint16) string { return netip.AddrPortFrom(addr, port).String() }

// TCP runs the tcp mode as an app and returns its result.
func (e *Env) TCP(name string, user User, args ...string) app.TCPResult {
	var r app.TCPResult
	e.RunJSON(Run{App: name, User: user, Args: append([]string{"tcp"}, args...), Timeout: 5 * time.Minute}, &r)
	return r
}

// Lines maps what servers saw to lines: line -> count ("?" for anything else).
func Lines(seen map[string]int) map[engine.LineID]int {
	out := map[engine.LineID]int{}
	for s, n := range seen {
		id := topo.LineOfText(s)
		if id == "" {
			id = "?"
		}
		out[id] += n
	}
	return out
}

// Describe prints a line count map in a stable order.
func Describe(m map[engine.LineID]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s:%d", k, m[engine.LineID(k)]))
	}
	return "{" + strings.Join(parts, " ") + "}"
}

// ExpectTCP checks that n whoami connections from an app all leave on line want.
func (e *Env) ExpectTCP(label, name string, user User, want engine.LineID, dst netip.Addr, n int) app.TCPResult {
	r := e.TCP(name, user, "--to", To(dst, wire.PortWhoami), "--count", strconv.Itoa(n), "--timeout", "5000")
	lines := Lines(r.Seen)
	e.T.Check(r.OK == n && lines[want] == n,
		"%s: %d/%d connections on line %s (lines %s, errors %v, connect p95 %.1f ms)", label, lines[want], n, want, Describe(lines), r.Errors, r.Connect.P95)
	return r
}

// UDP runs the udp mode as an app.
func (e *Env) UDP(name string, user User, args ...string) app.UDPResult {
	var r app.UDPResult
	e.RunJSON(Run{App: name, User: user, Args: append([]string{"udp"}, args...)}, &r)
	return r
}

// ExpectUDP checks that an app's datagrams are all answered and all left on want.
func (e *Env) ExpectUDP(label, name string, user User, want engine.LineID, dst netip.Addr, count int) app.UDPResult {
	r := e.UDP(name, user, "--to", To(dst, wire.PortUDPEcho), "--count", strconv.Itoa(count))
	lines := Lines(r.Seen)
	e.T.Check(r.Received == r.Sent && r.Sent == count && lines[want] == count,
		"%s: %d/%d datagrams answered, line %s saw %d (lines %s, send errors %v)", label, r.Received, r.Sent, want, lines[want], Describe(lines), r.SendErrors)
	return r
}

// FlowsOf filters flows by app path.
func FlowsOf(flows []engine.Flow, path string) []engine.Flow {
	var out []engine.Flow
	for _, f := range flows {
		if f.App == path {
			out = append(out, f)
		}
	}
	return out
}

// WaitFlow polls the engine's flows until match finds one, for up to timeout.
func (e *Env) WaitFlow(timeout time.Duration, match func(engine.Flow) bool) (engine.Flow, bool) {
	deadline := time.Now().Add(timeout)
	for {
		for _, f := range e.Flows() {
			if match(f) {
				return f, true
			}
		}
		if time.Now().After(deadline) || e.Ctx().Err() != nil {
			return engine.Flow{}, false
		}
		e.Sleep(100 * time.Millisecond)
	}
}

// WaitNoFlow polls the engine's flows until none matches, for up to timeout,
// and reports whether they all went.
func (e *Env) WaitNoFlow(timeout time.Duration, match func(engine.Flow) bool) ([]engine.Flow, bool) {
	deadline := time.Now().Add(timeout)
	for {
		var left []engine.Flow
		for _, f := range e.Flows() {
			if match(f) {
				left = append(left, f)
			}
		}
		if len(left) == 0 {
			return nil, true
		}
		if time.Now().After(deadline) || e.Ctx().Err() != nil {
			return left, false
		}
		e.Sleep(100 * time.Millisecond)
	}
}

// Stream is a long TCP connection's result.
type Stream = app.StreamResult

// StartStream opens a long connection to the stream server in the background.
func (e *Env) StartStream(name string, user User, duration time.Duration, extra ...string) *Bg {
	args := append([]string{"stream", "--to", To(topo.Server4, wire.PortStream), "--duration", strconv.Itoa(int(duration.Milliseconds())), "--interval", "100"}, extra...)
	return e.Start(Run{App: name, User: user, Args: args})
}

// StreamLines maps the lines a stream's pongs reported.
func StreamLines(s Stream) map[engine.LineID]int { return Lines(s.Seen) }

// CheckStreamSurvived checks a stream stayed open and kept answering on one line.
func (e *Env) CheckStreamSurvived(label string, s Stream, want engine.LineID) bool {
	lines := StreamLines(s)
	return e.T.Check(s.Connected && s.ClosedAt == 0 && s.MaxGapMS < 2000 && lines[want] == s.Pongs && s.Pongs > 0,
		"%s: stayed open on line %s (pongs %d of %d pings, lines %s, longest silence %d ms, closed %q)",
		label, want, s.Pongs, s.Pings, Describe(lines), s.MaxGapMS, s.CloseErr)
}

// ExpectSameState checks the PC's routing state matches before.
func (e *Env) ExpectSameState(label string, before topo.Snapshot) bool {
	now := e.Snapshot()
	diff := now.Diff(before)
	name := strings.NewReplacer(" ", "-", ",", "", ":", "").Replace(label)
	_ = now.Write(filepath.Join(e.T.Dir(), "state-"+name+".txt"))
	if len(diff) > 0 {
		e.T.Logf("%s: routing state differs:\n%s", label, strings.Join(diff, "\n"))
	}
	shown := diff
	if len(shown) > 4 {
		shown = append(slices.Clone(shown[:4]), fmt.Sprintf("... %d more", len(diff)-4))
	}
	return e.T.Check(len(diff) == 0, "%s: routing state is as before the engine started (%d differences: %s)", label, len(diff), strings.Join(shown, "; "))
}

// Cgroup makes a cgroup v2 folder for a case, inside the subtree delegated to
// the harness, and removes it afterwards.
func (e *Env) Cgroup(name string) string {
	if e.cfg.CgroupRoot == "" {
		e.T.Fatalf("the harness has no delegated cgroup subtree")
	}
	dir := filepath.Join(e.cfg.CgroupRoot, name)
	if err := os.Mkdir(dir, 0o755); err != nil {
		e.T.Fatalf("cgroup %s: %v", dir, err)
	}
	e.T.Cleanup(func() {
		for i := 0; i < 50; i++ {
			if os.Remove(dir) == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	})
	return dir
}

// SharedDir is a folder every test user can write, for files apps exchange.
// It's made fresh once per case.
func (e *Env) SharedDir() string {
	if e.sharedDir != "" {
		return e.sharedDir
	}
	dir := filepath.Join(os.TempDir(), "nsaccept-"+e.T.ID())
	if err := os.RemoveAll(dir); err != nil {
		e.T.Fatalf("shared dir: %v", err)
	}
	if err := os.MkdirAll(dir, 0o777); err != nil {
		e.T.Fatalf("shared dir: %v", err)
	}
	if err := os.Chmod(dir, 0o1777); err != nil {
		e.T.Fatalf("shared dir: %v", err)
	}
	e.T.Cleanup(func() { _ = os.RemoveAll(dir) })
	e.sharedDir = dir
	return dir
}
