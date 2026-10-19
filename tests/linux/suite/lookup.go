//go:build linux

package suite

import (
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/app"
	"github.com/AyoubAchour/net-switch/tests/linux/engine"
	"github.com/AyoubAchour/net-switch/tests/linux/harness"
	"github.com/AyoubAchour/net-switch/tests/linux/topo"
	"github.com/AyoubAchour/net-switch/tests/linux/wire"
)

// Section 5.6's Linux gates, on cold (newly created) sockets.
const (
	// "5,000+ open files held by the same user". 10,000 keeps the baseline's
	// measured cost (about 3 µs per file) clearly over the gate on arm64 too,
	// so the defect always reproduces.
	gateFiles       = 10000
	gateConnections = 300
	gateLatencyMS   = 10.0
	gateFound       = 0.995
)

func init() { register(50, addLookup) }

func addLookup(r *registry) {
	r.add("lookup.gate-terminal", "Owner lookup with 10,000 open files, from a plain terminal: p95 under 10 ms, owner found for 99.5%", harness.BaselineDefect, "5.6", 4*time.Minute,
		func(e *Env) { lookupGate(e, false) })
	r.add("lookup.gate-app-scope", "Owner lookup with 10,000 open files, app in its own scope: p95 under 10 ms, owner found for 99.5%", harness.BaselineDefect, "5.6", 4*time.Minute,
		func(e *Env) { lookupGate(e, true) })
	r.add("lookup.fork-exec", "A program started by another (fork and exec) is attributed to itself", harness.Parity, "5.6", 0, forkExec)
	r.add("lookup.inherited-socket", "A socket inherited by a child that alone holds it is the child's", harness.Parity, "5.6", 0, inheritedSocket)
	r.add("lookup.ambiguous-holders", "A socket held by two apps on different lines at once is treated as unknown", harness.BaselineDefect, "5.6", 0, ambiguousHolders)
	r.add("lookup.scm-rights-cross-user", "A socket handed to another user's app (SCM_RIGHTS) is that app's", harness.Parity, "5.6", 0, scmRightsCrossUser)
	r.add("lookup.cgroup-migration", "An app moved to another cgroup after making its socket is still found (the cgroup is only a hint)", harness.Parity, "5.6", 0, cgroupMigration)
}

func lookupGate(e *Env, scoped bool) {
	e.StartEngine(e.DefaultConfig())
	var appScope, terminal string
	if scoped {
		appScope = e.Cgroup("app-nsaccept-bravo-" + strconv.Itoa(os.Getpid()) + ".scope")
		terminal = e.Cgroup("app-nsaccept-terminal-" + strconv.Itoa(os.Getpid()) + ".scope")
	}
	whoami := To(topo.Server4, wire.PortWhoami)
	run := func(label string, args ...string) app.TCPResult {
		var r app.TCPResult
		e.RunJSON(Run{App: "bravo", Cgroup: appScope, Args: append([]string{"tcp", "--to", whoami, "--timeout", "5000"}, args...), Timeout: 3 * time.Minute}, &r)
		e.T.Logf("%s: %d ok, errors %v, connect p50 %.2f p95 %.2f max %.2f ms", label, r.OK, r.Errors, r.Connect.P50, r.Connect.P95, r.Connect.Max)
		return r
	}
	control := run("control, few open files", "--count", "100")
	holder := e.Start(Run{App: "alpha", Cgroup: terminal, Args: []string{"holdfiles", "--count", strconv.Itoa(gateFiles)}})
	holder.WaitOutput(e, "holding", 30*time.Second)
	cold := run("one at a time", "--count", strconv.Itoa(gateConnections))
	burst := run("ten at once", "--count", strconv.Itoa(gateConnections), "--concurrency", "10")
	holder.Stop()

	for _, m := range []struct {
		label string
		r     app.TCPResult
	}{{"one at a time", cold}, {"ten at once", burst}} {
		found := float64(Lines(m.r.Seen)["b"]) / float64(gateConnections)
		e.T.Check(found >= gateFound, "owner found (connection on bravo's line b) for %.1f%% of %d cold connections %s, with %d files open (gate %.1f%%)",
			100*found, gateConnections, m.label, gateFiles, 100*gateFound)
	}
	if v1, ok := e.Eng.(engine.V1); ok {
		stats, err := v1.Stats(e.Ctx())
		if err != nil {
			e.T.Fatalf("stats: %v", err)
		}
		ms := float64(stats.LookupP95.Microseconds()) / 1000
		e.T.Check(ms < gateLatencyMS, "the engine's own p95 lookup time is %.2f ms (gate %.0f ms)", ms, gateLatencyMS)
		return
	}
	// The baseline reports no lookup timings: estimate them as what the open
	// files add to connection setup.
	extra := cold.Connect.P95 - control.Connect.P50
	e.T.Note("connection setup p50 %.2f ms with few files; p95 %.2f ms with %d files (one at a time) and %.2f ms ten at once",
		control.Connect.P50, cold.Connect.P95, gateFiles, burst.Connect.P95)
	e.T.Check(extra < gateLatencyMS, "lookup cost (p95 setup with %d open files minus p50 without) is %.2f ms (gate %.0f ms)", gateFiles, extra, gateLatencyMS)
}

func forkExec(e *Env) {
	e.StartEngine(e.DefaultConfig())
	whoami := To(topo.Server4, wire.PortWhoami)
	for _, c := range []struct {
		parent, child string
		want          engine.LineID
	}{{"alpha", "charlie", "c"}, {"charlie", "alpha", "a"}, {"bravo", "charlie", "c"}} {
		var r app.TCPResult
		e.RunJSON(Run{App: c.parent, Args: []string{"spawn", "--", AppPath(c.child), "app", "tcp", "--to", whoami, "--count", "3"}}, &r)
		lines := Lines(r.Seen)
		e.T.Check(r.OK == 3 && lines[c.want] == 3, "%s started by %s uses %s's line %s (lines %s, errors %v)", c.child, c.parent, c.child, c.want, Describe(lines), r.Errors)
	}
}

func inheritedSocket(e *Env) {
	e.StartEngine(e.DefaultConfig())
	var r app.FDResult
	e.RunJSON(Run{App: "bravo", Args: []string{"share-exec", "--to", To(topo.Server4, wire.PortWhoami), "--child", AppPath("charlie"), "--keep=false"}}, &r)
	e.T.Check(r.Err == "" && topo.LineOfText(r.Seen) == "c", "bravo's socket, inherited and connected by charlie alone, is charlie's: line %q (%s)", topo.LineOfText(r.Seen), r.Err)
}

func ambiguousHolders(e *Env) {
	e.StartEngine(e.DefaultConfig())
	var r app.FDResult
	e.RunJSON(Run{App: "bravo", Args: []string{"share-exec", "--to", To(topo.Server4, wire.PortWhoami), "--child", AppPath("charlie"), "--keep=true"}}, &r)
	e.T.Check(r.Err == "" && topo.LineOfText(r.Seen) == "a",
		"a socket held by bravo (b) and charlie (c) at once is ambiguous, so unknown, so on the main line a: line %q (%s)", topo.LineOfText(r.Seen), r.Err)
}

func scmRightsCrossUser(e *Env) {
	e.StartEngine(e.DefaultConfig())
	sock := filepath.Join(e.SharedDir(), "pass.sock")
	recv := e.Start(Run{App: "charlie", User: AsOther, Args: []string{"fdpass-recv", "--unix", sock, "--to", To(topo.Server4, wire.PortWhoami)}})
	var sent map[string]any
	e.RunJSON(Run{App: "alpha", User: AsUser, Args: []string{"fdpass-send", "--unix", sock}}, &sent)
	var r app.FDResult
	recv.WaitJSON(e, 30*time.Second, &r)
	e.T.Require(r.Uid == e.cfg.Users.OtherUID, "the receiver ran as the second user (uid %d)", r.Uid)
	e.T.Check(r.Err == "" && topo.LineOfText(r.Seen) == "c",
		"alpha's socket (user %d), handed to charlie (user %d) and connected there, is charlie's: line %q (%s)", e.cfg.Users.UID, r.Uid, topo.LineOfText(r.Seen), r.Err)
}

func cgroupMigration(e *Env) {
	e.StartEngine(e.DefaultConfig())
	// The first scope's name points at charlie; bravo is moved out of it after
	// making its socket.
	from := e.Cgroup("app-nsaccept-charlie-" + strconv.Itoa(os.Getpid()) + ".scope")
	to := e.Cgroup("app-nsaccept-elsewhere-" + strconv.Itoa(os.Getpid()) + ".scope")
	trigger := filepath.Join(e.SharedDir(), "go")
	bg := e.Start(Run{App: "bravo", Cgroup: from, Args: []string{"tcp", "--presocket", "--wait-file", trigger, "--to", To(topo.Server4, wire.PortWhoami)}})
	e.Sleep(500 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(to, "cgroup.procs"), []byte(strconv.Itoa(bg.Pid())), 0); err != nil {
		e.T.Fatalf("move bravo: %v", err)
	}
	if err := os.WriteFile(trigger, nil, 0o644); err != nil {
		e.T.Fatalf("%v", err)
	}
	var r app.FDResult
	bg.WaitJSON(e, 30*time.Second, &r)
	e.T.Check(r.Err == "" && topo.LineOfText(r.Seen) == "b", "bravo, moved to another cgroup after creating its socket, stays on b: line %q (%s)", topo.LineOfText(r.Seen), r.Err)
}
