//go:build linux

package suite

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/app"
	"github.com/AyoubAchour/net-switch/tests/linux/engine"
	"github.com/AyoubAchour/net-switch/tests/linux/harness"
	"github.com/AyoubAchour/net-switch/tests/linux/inet"
	"github.com/AyoubAchour/net-switch/tests/linux/topo"
	"github.com/AyoubAchour/net-switch/tests/linux/wire"
)

// Section 5.9's Linux budgets. Each limit gets a case that reaches it while
// every other limit stays out of reach, so an engine missing any one of them
// fails. The baseline has none: that's the defect the count cases record.
const (
	udpSessionsPerApp = 4096
	udpSessionsTotal  = 16384
	tcpFlowsPerApp    = 8192
	tcpFlowsTotal     = 65536
	tcpHandshakes     = 8192
	tcpBufferBudget   = 256 << 20
	noticesPerApp     = 1000 // rejection notices a second
	noticesTotal      = 5000
)

func init() { register(55, addOverload) }

func addOverload(r *registry) {
	const noLimits = "sing-box has no per-app or total admission limits: it admits every session and connection it's asked for, and other flows can stall meanwhile"
	r.defect("overload.udp-sessions-per-app", "Two apps open 5,000 UDP sessions each: each gets at most 4,096 and the rest are refused, far under the total limit, while other traffic carries on",
		noLimits, "5.9", 3*time.Minute, udpSessionsPerAppCase)
	r.defect("overload.udp-sessions-total", "Five apps open 4,000 UDP sessions each, all under their own limit: together they get at most 16,384 and the rest are refused",
		noLimits, "5.9", 3*time.Minute, udpSessionsTotalCase)
	r.defect("overload.tcp-connection-storm", "A storm of 9,000 connections from one app, 300 at a time: at most 8,192 are admitted, the rest refused, while other apps carry on",
		noLimits, "5.9", 4*time.Minute, tcpStorm)
	r.defect("overload.tcp-handshakes-in-flight", "Three apps start 3,000 connections each to a host that never answers: at most 8,192 handshakes are in flight, the rest refused at once",
		noLimits, "5.9", 3*time.Minute, tcpHandshakesCase)
	r.defect("overload.tcp-flows-total", "Nine apps hold 7,600 connections each, all under their own limit: together at most 65,536 flows are admitted and the rest refused",
		noLimits, "5.9", 6*time.Minute, tcpFlowsTotalCase)
	r.add("overload.tcp-buffer-budget", "Forty fast transfers at once: TCP buffer growth stays within its 256 MiB budget and every transfer arrives intact",
		harness.Requires10, "5.9", 3*time.Minute, tcpBufferBudgetCase)
	r.add("overload.rejection-notice-rate", "Six capped apps open thousands of UDP sessions a second: refusal notices stay within 1,000 a second per app and 5,000 in total, and the rest are counted",
		harness.Requires10, "5.3, 5.9", 2*time.Minute, rejectionNoticeRate)
	r.pending("overload.udp-pending-bytes", "Pending UDP stays within 32 MiB in total and each new session's first-packet queue within 64 datagrams and 256 KiB; the excess is dropped and counted",
		"5.3, 5.9", "a test-build hook that holds owner lookups, so new sessions stay pending long enough to fill their queues on purpose")
	r.pending("overload.unknown-owner-limits", "Flows whose owner is unknown are capped at 2,048, and their UDP sessions at 512",
		"5.9", "a test-build hook that makes owner lookups miss, or another way to create owner-less flows from the PC at will")
	r.pending("overload.tun-write-queue", "The TUN write queue holds at most 1,024 packets; the rest are dropped and counted, and forwarding never blocks on it",
		"5.9", "a test-build hook that stalls the TUN writer")
	r.pending("overload.memory-at-limit", "At the GOMEMLIMIT target, the byte budgets still hold and no existing flow is cut to make room",
		"5.9", "a way to put the engine under memory pressure at its limit, and its heap size in stats")
}

// floodTargets are ten echo servers for the i-th flooding app.
func floodTargets(i int, port uint16) string {
	var dests []string
	for _, addr := range topo.ManyServers()[(i*10)%50 : (i*10)%50+10] {
		dests = append(dests, To(addr, port))
	}
	return strings.Join(dests, ",")
}

// udpFlood has each app open n UDP sessions, one datagram on each of n
// sockets at 800 new ones a second (any excess then arrives within the 1,000
// a second budget for refusal notices), and hold every socket until release
// opens, so every session counts against the limits at the same time.
func (e *Env) udpFlood(names []string, n int, release Release) (map[string]*Bg, map[string]app.FloodResult) {
	bgs := map[string]*Bg{}
	for i, name := range names {
		bgs[name] = e.Start(Run{App: name, Args: append([]string{"udpflood", "--to", floodTargets(i, wire.PortUDPEcho),
			"--sockets", strconv.Itoa(n), "--rate", "800", "--timeout", "4000"}, release.Arg()...)})
	}
	results := map[string]app.FloodResult{}
	for _, name := range names {
		var r app.FloodResult
		bgs[name].WaitHeld(e, "", 3*time.Minute, &r)
		e.T.Check(r.Opened == n && len(r.OpenErrors) == 0, "%s opened its %d sockets (%d, errors %v)", name, n, r.Opened, r.OpenErrors)
		results[name] = r
	}
	return bgs, results
}

// keptOpen is the mandatory half of "other traffic carries on" under
// overload: charlie's stream, open before it, was never closed and every
// answer came over its line. How long it may go quiet belongs with the
// limits in each case's defect assertion: without admission control an
// overloaded engine stalls other flows (the baseline went 3.2 s without an
// answer under 9,000 handshakes at once).
func (e *Env) keptOpen(label string, s Stream, want engine.LineID) {
	lines := StreamLines(s)
	e.T.Check(s.Connected && s.ClosedAt == 0 && s.Pongs > 0 && lines[want] == s.Pongs,
		"%s stayed open, every answer over line %s (pongs %d of %d pings, lines %s, closed %q)", label, want, s.Pongs, s.Pings, Describe(lines), s.CloseErr)
}

// responsive is the other half: no answer took more than 2 s.
func responsive(s Stream) bool { return s.MaxGapMS < 2000 }

// holding checks every app still holds what it opened, then lets them go.
func (e *Env) holding(bgs map[string]*Bg, release Release) {
	var gone []string
	for name, bg := range bgs {
		if !bg.Running() {
			gone = append(gone, name)
		}
	}
	e.T.Check(len(gone) == 0, "every app still held its sockets while the limits were measured (exited early: %v)", gone)
	release.Open(e)
	for _, bg := range bgs {
		bg.Wait(e, time.Minute)
	}
}

func describeFloods(names []string, results map[string]app.FloodResult) string {
	var parts []string
	for _, name := range names {
		r := results[name]
		parts = append(parts, fmt.Sprintf("%s %d answered, %d refused, %d silent", name, r.Answered, r.Refused, r.Silent))
	}
	return strings.Join(parts, "; ")
}

func udpSessionsPerAppCase(e *Env) {
	e.StartEngine(e.DefaultConfig())
	// The stream runs until the flood lets go.
	release := e.NewRelease("udp-per-app")
	stream := e.StartStream("charlie", AsUser, 3*time.Minute, release.Arg()...)
	e.Sleep(time.Second)
	// 904 sessions over each app's limit; the two apps together stay far
	// under the total, so only the per-app limit can refuse.
	const perApp = 5000
	names := []string{"alpha", "bravo"}
	bgs, results := e.udpFlood(names, perApp, release)
	e.ExpectTCP("foxtrot during the flood", "foxtrot", AsUser, "a", topo.Server4, 3)
	minAnswered, maxAnswered, minRefused, total := perApp, 0, perApp, 0
	for _, name := range names {
		r := results[name]
		minAnswered, maxAnswered, minRefused = min(minAnswered, r.Answered), max(maxAnswered, r.Answered), min(minRefused, r.Refused)
		total += r.Answered
	}
	e.T.Check(total < udpSessionsTotal*3/4, "the two apps together stay far from the total limit (%d answered)", total)
	e.T.Check(minAnswered >= udpSessionsPerApp*95/100, "each app still got at least 95%% of its allowed %d sessions served (least: %d; %s)", udpSessionsPerApp, minAnswered, describeFloods(names, results))
	e.holding(bgs, release)
	var s Stream
	stream.WaitJSON(e, 30*time.Second, &s)
	e.keptOpen("charlie's stream through the flood", s, "c")
	e.T.Check(e.Eng.Running(), "the engine is still running")
	// Losing sessions at random isn't a limit: the excess must be refused.
	excess := perApp - udpSessionsPerApp
	e.T.Expect(maxAnswered <= udpSessionsPerApp && minRefused >= excess*9/10 && responsive(s),
		"no app gets more than %d sessions and each app's %d extra are refused, while charlie's stream never waits 2 s for an answer (most for one app %d, fewest refused %d, longest silence %d ms; %s)",
		udpSessionsPerApp, excess, maxAnswered, minRefused, s.MaxGapMS, describeFloods(names, results))
}

func udpSessionsTotalCase(e *Env) {
	e.StartEngine(e.DefaultConfig())
	release := e.NewRelease("udp-total")
	stream := e.StartStream("charlie", AsUser, 3*time.Minute, release.Arg()...)
	e.Sleep(time.Second)
	// Every app stays under its own 4,096; together they ask for 20,000, so
	// only the total limit can refuse.
	const perApp = 4000
	names := []string{"alpha", "bravo", "delta", "golf", "hotel"}
	bgs, results := e.udpFlood(names, perApp, release)
	e.ExpectTCP("foxtrot during the flood", "foxtrot", AsUser, "a", topo.Server4, 3)
	total, refused := 0, 0
	for _, name := range names {
		total += results[name].Answered
		refused += results[name].Refused
	}
	e.T.Check(total >= udpSessionsTotal*95/100, "together the apps still got at least 95%% of the %d sessions allowed in total (%d; %s)", udpSessionsTotal, total, describeFloods(names, results))
	e.holding(bgs, release)
	var s Stream
	stream.WaitJSON(e, 30*time.Second, &s)
	e.keptOpen("charlie's stream through the flood", s, "c")
	e.T.Check(e.Eng.Running(), "the engine is still running")
	asked := perApp * len(names)
	excess := asked - udpSessionsTotal
	e.T.Expect(total <= udpSessionsTotal && refused >= excess*9/10 && responsive(s),
		"all together no more than %d of the %d sessions are admitted and the %d extra are refused, while charlie's stream never waits 2 s for an answer (%d answered, %d refused, longest silence %d ms; %s)",
		udpSessionsTotal, asked, excess, total, refused, s.MaxGapMS, describeFloods(names, results))
}

func tcpStorm(e *Env) {
	e.StartEngine(e.DefaultConfig())
	release := e.NewRelease("storm")
	stream := e.StartStream("charlie", AsUser, 3*time.Minute, release.Arg()...)
	e.Sleep(time.Second)
	// 300 at a time keeps the handshakes in flight far under their own
	// limit, and 9,000 flows are far under the total: only the per-app
	// limit can refuse.
	const storm = 9000
	hold := e.Start(Run{App: "bravo", Args: append([]string{"tcphold", "--to", floodTargets(0, wire.PortHold), "--count", strconv.Itoa(storm),
		"--concurrency", "300", "--timeout", "5000"}, release.Arg()...)})
	hold.WaitLine(e, "holding ", 3*time.Minute)
	e.ExpectTCP("foxtrot during the storm", "foxtrot", AsUser, "a", topo.Server4, 3)
	e.T.Check(hold.Running(), "bravo still holds its connections")
	release.Open(e)
	var r app.HoldResult
	hold.WaitJSON(e, time.Minute, &r)
	refused := r.Errors["ECONNREFUSED"] + r.Errors["ECONNRESET"]
	e.T.Check(r.Established >= tcpFlowsPerApp*95/100, "bravo still got at least 95%% of its allowed %d connections (%d established, errors %v)", tcpFlowsPerApp, r.Established, r.Errors)
	e.T.Check(r.StillOpen == r.Established, "admitted connections stay open (%d of %d)", r.StillOpen, r.Established)
	var s Stream
	stream.WaitJSON(e, 30*time.Second, &s)
	e.keptOpen("charlie's stream through the storm", s, "c")
	e.T.Check(e.Eng.Running(), "the engine is still running")
	e.T.Expect(r.Established <= tcpFlowsPerApp && refused == storm-r.Established && r.FailedMS.Max < 3000 && responsive(s),
		"at most %d of %d are admitted and every other one is refused within 3 s, while charlie's stream never waits 2 s for an answer (%d admitted, %d refused, slowest refusal %.0f ms, longest silence %d ms, errors %v)",
		tcpFlowsPerApp, storm, r.Established, refused, r.FailedMS.Max, s.MaxGapMS, r.Errors)
}

func tcpHandshakesCase(e *Env) {
	e.StartEngine(e.DefaultConfig())
	streamEnd := e.NewRelease("stream")
	stream := e.StartStream("charlie", AsUser, 3*time.Minute, streamEnd.Arg()...)
	e.Sleep(time.Second)
	// Every SYN to the black hole goes unanswered, so each admitted
	// connection stays in its handshake. 9,000 at once from three apps is
	// 808 over the in-flight limit, while each app (3,000) and the total stay
	// far under their own.
	const perApp, window = 3000, 3000
	names := []string{"alpha", "bravo", "delta"}
	bgs := map[string]*Bg{}
	for i, name := range names {
		bgs[name] = e.Start(Run{App: name, Args: []string{"tcphold", "--to", floodTargets(i, wire.PortBlackhole), "--count", strconv.Itoa(perApp),
			"--concurrency", strconv.Itoa(perApp), "--timeout", "15000", "--window", strconv.Itoa(window), "--hold", "0"}})
	}
	pending, refused, completed := 0, 0, 0
	var parts []string
	for _, name := range names {
		var r app.HoldResult
		bgs[name].WaitJSON(e, time.Minute, &r)
		pending += r.PendingAt
		refused += r.RefusedWithin
		completed += r.Established
		parts = append(parts, fmt.Sprintf("%s: %d in flight at %d ms, %d refused before, errors %v", name, r.PendingAt, window, r.RefusedWithin, r.Errors))
	}
	e.T.Check(completed == 0, "no handshake to the black hole completed: nothing answers there, so a completed one was faked (%d)", completed)
	e.T.Check(pending >= tcpHandshakes*95/100, "at least 95%% of the %d handshakes allowed were in flight (%d; %s)", tcpHandshakes, pending, strings.Join(parts, "; "))
	e.T.Check(e.Eng.Running(), "the engine is still running")
	e.retryLine("foxtrot's new connections once the handshakes have given up", "foxtrot", "a", 10*time.Second)
	streamEnd.Open(e)
	var s Stream
	stream.WaitJSON(e, 30*time.Second, &s)
	e.keptOpen("charlie's stream, open before the handshakes,", s, "c")
	asked := perApp * len(names)
	e.T.Expect(pending <= tcpHandshakes && refused >= (asked-tcpHandshakes)*9/10 && responsive(s),
		"at most %d of %d handshakes are in flight at once and the %d extra are refused within %d ms, while charlie's stream never waits 2 s for an answer (%d in flight, %d refused, longest silence %d ms; %s)",
		tcpHandshakes, asked, asked-tcpHandshakes, window, pending, refused, s.MaxGapMS, strings.Join(parts, "; "))
}

// raiseConntrack lifts the kernel's connection tracking limit for a case
// that opens tens of thousands of connections, so a router's table can't be
// what refuses them. It's restored afterwards.
func (e *Env) raiseConntrack(to int) {
	const path = "/proc/sys/net/netfilter/nf_conntrack_max"
	old, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return // no connection tracking loaded at all
	}
	if err != nil {
		e.T.Fatalf("%v", err)
	}
	if err := os.WriteFile(path, []byte(strconv.Itoa(to)), 0o644); err != nil {
		e.T.Fatalf("raising %s: %v", path, err)
	}
	e.T.Cleanup(func() {
		if err := os.WriteFile(path, old, 0o644); err != nil {
			e.T.Check(false, "restoring %s to %s (%v)", path, strings.TrimSpace(string(old)), err)
		}
	})
}

func tcpFlowsTotalCase(e *Env) {
	// Nine apps hold 7,600 connections each (68,400), every app under its
	// own 8,192 and 100 at a time per app far under the handshake limit:
	// only the total can refuse. All on line c, which isn't NATed, so no
	// router keeps state for them.
	const perApp = 7600
	names := []string{"alpha", "bravo", "delta", "foxtrot", "golf", "hotel", "india", "juliett", "kilo"}
	cfg := e.DefaultConfig()
	cfg.Policy.Pins = []engine.Pin{{App: e.App("charlie"), Line: "c"}}
	for _, name := range names {
		cfg.Policy.Pins = append(cfg.Policy.Pins, engine.Pin{App: e.App(name), Line: "c"})
	}
	e.raiseConntrack(1 << 20)
	e.StartEngine(cfg)
	// charlie's stream, itself a flow, runs until the apps let go.
	release := e.NewRelease("flows")
	stream := e.StartStream("charlie", AsUser, 6*time.Minute, release.Arg()...)
	e.Sleep(time.Second)
	from := time.Now().UnixMilli()
	bgs := map[string]*Bg{}
	for i, name := range names {
		bgs[name] = e.Start(Run{App: name, Args: append([]string{"tcphold", "--to", floodTargets(i, wire.PortHold), "--count", strconv.Itoa(perApp),
			"--concurrency", "100", "--timeout", "10000"}, release.Arg()...)})
	}
	established := 0
	for _, name := range names {
		line := bgs[name].WaitLine(e, "holding ", 4*time.Minute)
		n, err := strconv.Atoi(strings.TrimPrefix(line, "holding "))
		if err != nil {
			e.T.Fatalf("%s: %q", name, line)
		}
		established += n
	}
	// The servers' own count of what got out, while everything is held.
	isHold := func(r inet.Record) bool {
		return r.Kind == "tcp" && r.T >= from && strings.HasSuffix(r.Dst, ":"+strconv.Itoa(wire.PortHold))
	}
	recs, _ := e.WaitRecords(10*time.Second, func(recs []inet.Record) bool { return len(Select(recs, isHold)) >= established })
	accepted := Select(recs, isHold)
	e.T.Check(len(accepted) == established && RecordLines(accepted)["c"] == len(accepted),
		"the servers accepted exactly the %d connections the apps hold, all over line c (%d accepted, lines %s)", established, len(accepted), Describe(RecordLines(accepted)))
	e.T.Check(established >= tcpFlowsTotal*95/100, "together the apps still got at least 95%% of the %d flows allowed in total (%d)", tcpFlowsTotal, established)
	release.Open(e)
	refused, stillOpen := 0, 0
	var parts []string
	for _, name := range names {
		var r app.HoldResult
		bgs[name].WaitJSON(e, 2*time.Minute, &r)
		refused += r.Errors["ECONNREFUSED"] + r.Errors["ECONNRESET"]
		stillOpen += r.StillOpen
		parts = append(parts, fmt.Sprintf("%s %d", name, r.Established))
	}
	e.T.Check(stillOpen == established, "every admitted connection was still open when released (%d of %d)", stillOpen, established)
	var s Stream
	stream.WaitJSON(e, 30*time.Second, &s)
	e.keptOpen("charlie's stream, one of the flows,", s, "c")
	e.T.Check(e.Eng.Running(), "the engine is still running")
	asked := perApp * len(names)
	// charlie's stream is a flow too.
	room := tcpFlowsTotal - 1
	e.T.Expect(established <= room && refused >= (asked-room)*9/10 && responsive(s),
		"at most %d of the %d connections are admitted besides charlie's stream and the %d extra are refused, while the stream never waits 2 s for an answer (%d admitted, %d refused, longest silence %d ms; %s)",
		room, asked, asked-room, established, refused, s.MaxGapMS, strings.Join(parts, ", "))
}

func tcpBufferBudgetCase(e *Env) {
	e.StartEngine(e.DefaultConfig())
	_, s := e.v1()
	// Forty 64 MiB downloads at once want more buffer than the budget: up to
	// 14 MiB each above the 64 KiB floor (5.9).
	const transfers, size = 40, 64 << 20
	var bgs []*Bg
	for range transfers {
		bgs = append(bgs, e.Start(Run{App: "charlie", Args: []string{"bulk", "--to", To(topo.Server4, wire.PortBulk), "--bytes", strconv.Itoa(size), "--timeout", "120000"}}))
	}
	most, samples := int64(0), 0
	for {
		st, err := s.Stats(e.Ctx())
		e.T.Require(err == nil, "stats during the transfers (%v)", err)
		most = max(most, st.TCPBytes)
		samples++
		running := 0
		for _, bg := range bgs {
			if bg.Running() {
				running++
			}
		}
		if running == 0 || e.Ctx().Err() != nil {
			break
		}
		e.Sleep(100 * time.Millisecond)
	}
	intact := 0
	for _, bg := range bgs {
		var r app.BulkResult
		bg.WaitJSON(e, time.Minute, &r)
		if r.OK {
			intact++
		}
	}
	e.T.Check(intact == transfers, "all %d transfers arrived intact (%d)", transfers, intact)
	e.T.Check(most > 0, "the transfers grew buffers above the floor at some point (%d samples, most %d bytes)", samples, most)
	e.T.Check(most <= tcpBufferBudget, "buffer growth never went over the %d MiB budget (most %.1f MiB over %d samples)", tcpBufferBudget>>20, float64(most)/(1<<20), samples)
}

func rejectionNoticeRate(e *Env) {
	// Six capped apps, each opening 2,500 new sessions a second: 2.5 times
	// the per-app budget, and 15,000 a second all together, three times the
	// total.
	names := []string{"alpha", "bravo", "delta", "foxtrot", "golf", "hotel"}
	cfg := e.DefaultConfig()
	cfg.Policy.Pins = nil
	for _, name := range names {
		cfg.Policy.Pins = append(cfg.Policy.Pins, engine.Pin{App: e.App(name), Line: "c"})
	}
	cfg.Policy.Blocked = []engine.LineID{"c"}
	e.StartEngine(cfg)
	_, s := e.v1()
	before, err := s.Stats(e.Ctx())
	e.T.Require(err == nil, "stats (%v)", err)
	from := time.Now().UnixMilli()
	bgs := map[string]*Bg{}
	for i, name := range names {
		bgs[name] = e.Start(Run{App: name, Args: []string{"udpflood", "--to", floodTargets(i, wire.PortUDPEcho), "--sockets", "5000", "--rate", "2500", "--timeout", "2000", "--times"}})
	}
	perSecond := map[int64]int{}
	worstApp, sent, notified := 0, 0, 0
	for _, name := range names {
		var r app.FloodResult
		bgs[name].WaitJSON(e, time.Minute, &r)
		sent += r.Opened
		notified += r.Refused
		mine := map[int64]int{}
		for _, t := range r.RefusedAt {
			mine[t/1000]++
			perSecond[t/1000]++
		}
		for _, n := range mine {
			worstApp = max(worstApp, n)
		}
		e.T.Check(r.Answered == 0, "none of capped %s's datagrams was answered (%d)", name, r.Answered)
	}
	worst := 0
	for _, n := range perSecond {
		worst = max(worst, n)
	}
	e.Sleep(500 * time.Millisecond)
	escaped := Select(e.Records(), func(r inet.Record) bool { return r.Kind == "udp" && r.T >= from })
	e.T.Check(len(escaped) == 0, "nothing the capped apps sent got out (%d datagrams reached the servers)", len(escaped))
	after, err := s.Stats(e.Ctx())
	e.T.Require(err == nil, "stats (%v)", err)
	// A notice sent just before a second ends can arrive just after it.
	e.T.Check(worstApp <= noticesPerApp*105/100, "no app got more than %d refusal notices in any second (most %d)", noticesPerApp, worstApp)
	e.T.Check(worst <= noticesTotal*105/100, "all together no more than %d refusal notices in any second (most %d)", noticesTotal, worst)
	e.T.Check(notified > 0 && after.DroppedNotices-before.DroppedNotices >= uint64(sent-notified)*9/10,
		"the notices held back were counted (%d sessions refused, %d told, %d counted as dropped)", sent, notified, after.DroppedNotices-before.DroppedNotices)
}
