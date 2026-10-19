//go:build linux

package suite

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
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
	const slow = "sing-box scans every open file of the socket's user on each new connection (about 3 µs per file), so its estimated p95 lookup is well over 10 ms"
	r.defect("lookup.gate-terminal", "Owner lookup with 10,000 open files, from a plain terminal: owner found for 99.5% (p95: an estimate here, measured in lookup.p95-measured)", slow, "5.6", 4*time.Minute,
		func(e *Env) { lookupGate(e, false, false) })
	r.defect("lookup.gate-app-scope", "Owner lookup with 10,000 open files, app in its own scope: owner found for 99.5% (p95: an estimate here, measured in lookup.p95-measured)", slow, "5.6", 4*time.Minute,
		func(e *Env) { lookupGate(e, true, false) })
	r.add("lookup.p95-measured", "The engine's own p95 owner-lookup time stays under 10 ms with 10,000 open files, in an app scope and from a plain terminal",
		harness.Requires10, "5.6", 8*time.Minute, func(e *Env) { lookupGate(e, false, true); e.StopEngine(); lookupGate(e, true, true) })
	r.add("lookup.fork-exec", "A program started by another (fork and exec) is attributed to itself", harness.Parity, "5.6", 0, forkExec)
	r.add("lookup.inherited-socket", "A socket inherited by a child that alone holds it is the child's", harness.Parity, "5.6", 0, inheritedSocket)
	r.defect("lookup.ambiguous-holders", "A socket held by two apps on different lines at once is treated as unknown",
		"the first holder found wins, so the socket takes that app's line instead of the main line", "5.6", 0, ambiguousHolders)
	r.add("lookup.scm-rights-cross-user", "A socket handed to another user's app (SCM_RIGHTS) is that app's", harness.Parity, "5.6", 0, scmRightsCrossUser)
	r.add("lookup.cgroup-migration", "An app moved to another cgroup after making its socket is still found (the cgroup is only a hint)", harness.Parity, "5.6", 0, cgroupMigration)
}

// phase is one loaded measurement: cold connections with the files open.
type phase struct {
	label string
	r     app.TCPResult
	// The engine's own lookup counters for the phase (1.0), from stats read
	// just before and after it.
	lookups, misses uint64
	lookupTime      time.Duration
	histogram       [201]uint64
}

func lookupGate(e *Env, scoped, measured bool) {
	e.StartEngine(e.DefaultConfig())
	var session engine.Controller
	if v1, ok := e.Eng.(engine.V1); ok {
		session = v1.Session()
	}
	stats := func() engine.Stats {
		s, err := session.Stats(e.Ctx())
		if err != nil {
			e.T.Fatalf("stats: %v", err)
		}
		return s
	}
	var appScope, terminal string
	if scoped {
		appScope = e.Cgroup("app-nsaccept-bravo-" + strconv.Itoa(os.Getpid()) + ".scope")
		terminal = e.Cgroup("app-nsaccept-terminal-" + strconv.Itoa(os.Getpid()) + ".scope")
	}
	whoami := To(topo.Server4, wire.PortWhoami)
	run := func(label string, args ...string) phase {
		p := phase{label: label}
		var before engine.Stats
		if session != nil {
			before = stats()
		}
		e.RunJSON(Run{App: "bravo", Cgroup: appScope, Args: append([]string{"tcp", "--to", whoami, "--timeout", "5000"}, args...), Timeout: 3 * time.Minute}, &p.r)
		if session != nil {
			after := stats()
			if scoped {
				var hints struct{ CgroupPopulated uint64 }
				err := json.Unmarshal(after.OwnerLookup, &hints)
				e.T.Check(err == nil && hints.CgroupPopulated > 0, "the scoped phase actually resolved cgroup hints inside the engine (%d populated hints; %v)", hints.CgroupPopulated, err)
			}
			p.lookups, p.misses, p.lookupTime = after.LookupCount-before.LookupCount, after.LookupMisses-before.LookupMisses, after.LookupTime-before.LookupTime
			for i := range p.histogram {
				p.histogram[i] = after.LookupHistogram[i] - before.LookupHistogram[i]
			}
		}
		e.T.Logf("%s: %d ok, errors %v, connect p50 %.2f p95 %.2f max %.2f ms", label, p.r.OK, p.r.Errors, p.r.Connect.P50, p.r.Connect.P95, p.r.Connect.Max)
		return p
	}
	// Every connection gets a source port never used before in the case, so
	// a reused port's TIME_WAIT (5.1, a separate defect) can't stall it.
	control := run("control, few open files", "--count", "100", "--port-base", "20000")
	holder := e.Start(Run{App: "alpha", Cgroup: terminal, Args: []string{"holdfiles", "--count", strconv.Itoa(gateFiles)}})
	holder.WaitOutput(e, "{\"holding\"", 30*time.Second)
	phases := []phase{
		run("one at a time", "--count", strconv.Itoa(gateConnections), "--port-base", "20100"),
		run("ten at once", "--count", strconv.Itoa(gateConnections), "--concurrency", "10", "--port-base", "20400"),
	}
	holder.Stop()

	// Section 5.6's gate is two numbers, per phase: owner found (the
	// connection on bravo's line b, as the servers saw it) for 99.5%, and
	// p95 lookup under 10 ms. Completing the connections is a prerequisite.
	var verdicts []string
	ok := true
	for _, p := range phases {
		e.T.Check(p.r.OK == gateConnections, "all %d cold connections %s completed (%d; errors %v)", gateConnections, p.label, p.r.OK, p.r.Errors)
		found := float64(Lines(p.r.Seen)["b"]) / float64(gateConnections)
		ok = ok && found >= gateFound
		verdicts = append(verdicts, fmt.Sprintf("%s: owner found for %.1f%%", p.label, 100*found))
	}
	if session == nil {
		// The baseline reports no lookup timings, so its p95 can only be
		// estimated from outside: what the open files add to connection setup
		// (setup p95 with them minus the median without). An estimate can show
		// the baseline missing the gate; it can never pass 1.0's, which needs
		// the engine's own per-lookup timings (lookup.p95-measured).
		for _, p := range phases {
			extra := p.r.Connect.P95 - control.r.Connect.P50
			ok = ok && extra < gateLatencyMS
			verdicts = append(verdicts, fmt.Sprintf("%s: p95 ESTIMATED at %.2f ms (setup p95 %.2f minus %.2f without the files)", p.label, extra, p.r.Connect.P95, control.r.Connect.P50))
		}
		e.T.Expect(ok, "with %d open files, each phase finds the owner for at least %.1f%%, and the outside estimate of p95 lookup is under %.0f ms (%s)",
			gateFiles, 100*gateFound, gateLatencyMS, strings.Join(verdicts, "; "))
		return
	}
	// 1.0: the engine's own counts for exactly each phase must agree that
	// the owners were found. Its p95 is lookup.p95-measured's to prove;
	// nothing here stands in for it.
	for _, p := range phases {
		e.T.Check(p.lookups >= gateConnections, "the engine counted %d lookups %s (at least %d)", p.lookups, p.label, gateConnections)
		found, mean := 0.0, time.Duration(0)
		if p.lookups > 0 {
			found = 1 - float64(p.misses)/float64(p.lookups)
			mean = p.lookupTime / time.Duration(p.lookups)
		}
		ok = ok && found >= gateFound
		verdicts = append(verdicts, fmt.Sprintf("%s: the engine found %.1f%% of %d owners (mean lookup %v, for the record)", p.label, 100*found, p.lookups, mean))
		var count, cumulative uint64
		for _, n := range p.histogram {
			count += n
		}
		p95 := 20100 * time.Microsecond
		for i, n := range p.histogram {
			cumulative += n
			if count > 0 && cumulative >= (count*95+99)/100 {
				p95 = time.Duration(i+1) * 100 * time.Microsecond
				break
			}
		}
		e.T.Check(count == p.lookups && count >= gateConnections, "histogram contains every measured cold lookup (%d buckets, %d lookups)", count, p.lookups)
		e.T.Check(p95 < 10*time.Millisecond, "%s (app scope %v): measured lookup p95 upper bound %v is under 10 ms", p.label, scoped, p95)
	}
	check := e.T.Expect
	if measured {
		check = e.T.Check
	}
	check(ok, "with %d open files, each phase finds the owner for at least %.1f%%, as the servers and the engine both count (%s)",
		gateFiles, 100*gateFound, strings.Join(verdicts, "; "))
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

// shared starts bravo handing a socket to a charlie child, waits until the
// hand-off is complete, checks who holds the socket, then lets charlie
// connect.
func (e *Env) shared(keep bool, wantHolders []string) app.FDResult {
	e.StartEngine(e.DefaultConfig())
	trigger := filepath.Join(e.SharedDir(), "go")
	bg := e.Start(Run{App: "bravo", Args: []string{"share-exec", "--to", To(topo.Server4, wire.PortWhoami), "--child", AppPath("charlie"), "--keep=" + strconv.FormatBool(keep), "--wait-file", trigger}})
	inode, _ := e.ParseReady(bg.WaitLine(e, "ready ", 30*time.Second))
	holders := e.Holders(inode)
	var names []string
	for _, h := range holders {
		names = append(names, filepath.Base(filepath.Dir(h.Exe)))
	}
	slices.Sort(names)
	e.T.Require(slices.Equal(names, wantHolders), "before charlie connects, socket %d is held by %v (%v)", inode, wantHolders, holders)
	if err := os.WriteFile(trigger, nil, 0o644); err != nil {
		e.T.Fatalf("%v", err)
	}
	var r app.FDResult
	bg.WaitJSON(e, 30*time.Second, &r)
	e.T.Require(r.Inode == inode, "charlie connected the same socket (%d)", r.Inode)
	return r
}

func inheritedSocket(e *Env) {
	r := e.shared(false, []string{"charlie"})
	e.T.Check(r.Err == "" && topo.LineOfText(r.Seen) == "c", "bravo's socket, inherited and connected by charlie alone, is charlie's: line %q (%s)", topo.LineOfText(r.Seen), r.Err)
}

func ambiguousHolders(e *Env) {
	r := e.shared(true, []string{"bravo", "charlie"})
	e.T.Check(r.Err == "" && r.Seen != "", "charlie's connection completed (%s)", r.Err)
	e.T.Expect(topo.LineOfText(r.Seen) == "a",
		"a socket held by bravo (b) and charlie (c) at once is ambiguous, so unknown, so on the main line a: line %q", topo.LineOfText(r.Seen))
}

func scmRightsCrossUser(e *Env) {
	e.StartEngine(e.DefaultConfig())
	dir := e.SharedDir()
	sock, trigger := filepath.Join(dir, "pass.sock"), filepath.Join(dir, "go")
	recv := e.Start(Run{App: "charlie", User: AsOther, Args: []string{"fdpass-recv", "--unix", sock, "--to", To(topo.Server4, wire.PortWhoami), "--wait-file", trigger}})
	send := e.Start(Run{App: "alpha", User: AsUser, Args: []string{"fdpass-send", "--unix", sock}})
	inode, pid := e.ParseReady(recv.WaitLine(e, "ready ", 30*time.Second))
	holders := e.Holders(inode)
	e.T.Require(slices.Equal(HolderPids(holders), []int{pid}), "after the hand-off only the receiver (pid %d) holds socket %d (%v)", pid, inode, holders)
	if err := os.WriteFile(trigger, nil, 0o644); err != nil {
		e.T.Fatalf("%v", err)
	}
	var r app.FDResult
	recv.WaitJSON(e, 30*time.Second, &r)
	var sent struct {
		Inode uint64 `json:"inode"`
		Uid   int    `json:"uid"`
	}
	send.WaitJSON(e, 30*time.Second, &sent)
	e.T.Require(r.Uid == e.cfg.Users.OtherUID && sent.Uid == e.cfg.Users.UID && sent.Inode == inode,
		"alpha (user %d) made socket %d and charlie (user %d) connected it", sent.Uid, sent.Inode, r.Uid)
	e.T.Check(r.Err == "" && topo.LineOfText(r.Seen) == "c",
		"alpha's socket, handed to charlie and connected there, is charlie's: line %q (%s)", topo.LineOfText(r.Seen), r.Err)
}

func cgroupMigration(e *Env) {
	e.StartEngine(e.DefaultConfig())
	// The first scope's name points at charlie; bravo is moved out of it after
	// making its socket.
	from := e.Cgroup("app-nsaccept-charlie-" + strconv.Itoa(os.Getpid()) + ".scope")
	to := e.Cgroup("app-nsaccept-elsewhere-" + strconv.Itoa(os.Getpid()) + ".scope")
	trigger := filepath.Join(e.SharedDir(), "go")
	bg := e.Start(Run{App: "bravo", Cgroup: from, Args: []string{"tcp", "--presocket", "--wait-file", trigger, "--to", To(topo.Server4, wire.PortWhoami)}})
	inode, pid := e.ParseReady(bg.WaitLine(e, "ready ", 30*time.Second))
	rel := func(dir string) string { return strings.TrimPrefix(dir, "/sys/fs/cgroup") }
	e.T.Require(CgroupOf(pid) == rel(from), "bravo made socket %d in %s (it's in %s)", inode, rel(from), CgroupOf(pid))
	if err := os.WriteFile(filepath.Join(to, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0); err != nil {
		e.T.Fatalf("move bravo: %v", err)
	}
	holders := e.Holders(inode)
	e.T.Require(len(holders) == 1 && holders[0].Pid == pid && holders[0].Cgroup == rel(to),
		"after the move, only bravo holds the socket, from %s (%v)", rel(to), holders)
	if err := os.WriteFile(trigger, nil, 0o644); err != nil {
		e.T.Fatalf("%v", err)
	}
	var r app.FDResult
	bg.WaitJSON(e, 30*time.Second, &r)
	e.T.Check(r.Err == "" && topo.LineOfText(r.Seen) == "b", "bravo, moved to another cgroup after creating its socket, stays on b: line %q (%s)", topo.LineOfText(r.Seen), r.Err)
}
