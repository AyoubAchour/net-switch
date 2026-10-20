//go:build linux

package suite

import (
	"context"
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
	r.add("overload.tcp-buffer-budget", "64 downloads that each earn the 6 MiB send buffer and keep it: growth fills the 256 MiB budget, is refused beyond it, and every byte arrives intact",
		harness.Requires10, "5.9", 4*time.Minute, tcpBufferBudgetCase)
	r.add("overload.rejection-notices-per-app", "One capped app opens 3,000 UDP sessions a second on its own: it gets about 1,000 refusal notices a second, never more, and the rest are counted",
		harness.Requires10, "5.3, 5.9", 2*time.Minute, rejectionNoticesPerApp)
	r.add("overload.rejection-notices-total", "Eight capped apps open 800 UDP sessions a second each, all under their own limit: together they get about 5,000 refusal notices a second, never more",
		harness.Requires10, "5.3, 5.9", 2*time.Minute, rejectionNoticesTotal)
	r.add("overload.timewait-cap", "5,000 server-closed connections in 15 s: TIME_WAIT holds at most 4,096 endpoints, they aren't live flows, the rest skip it, and no connection is refused",
		harness.Requires10, "5.9", 3*time.Minute, timeWaitCap)
	r.add("overload.udp-pending-bytes", "Pending UDP stays within 32 MiB in total and each new session's first-packet queue within 64 datagrams and 256 KiB; the excess is dropped and counted",
		harness.Requires10, "5.3, 5.9", 2*time.Minute, pendingBytes)
	r.add("overload.unknown-owner-limits", "Flows whose owner is unknown are capped at 2,048, and their UDP sessions at 512",
		harness.Requires10, "5.9", 3*time.Minute, unknownLimits)
	r.add("overload.tun-write-queue", "The TUN write queue holds at most 1,024 packets; the rest are dropped and counted, and forwarding never blocks on it",
		harness.Requires10, "5.9", 2*time.Minute, tunQueue)
	r.add("overload.memory-at-limit", "At the GOMEMLIMIT target, the byte budgets still hold and no existing flow is cut to make room",
		harness.Requires10, "5.9", 4*time.Minute, memoryLimit)
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
		e.T.Check(r.Opened == n && r.Sent == n && len(r.OpenErrors) == 0 && len(r.SendErrors) == 0,
			"%s opened its %d sockets and sent on each (%d opened, %d sent, errors %v %v)", name, n, r.Opened, r.Sent, r.OpenErrors, r.SendErrors)
		results[name] = r
	}
	return bgs, results
}

// sessions is what one app's flood became, from three sides that don't
// depend on each other: the app (answers and ICMP refusals, per socket), the
// servers (which sockets' datagrams reached them) and the engine (the UDP
// sessions it lists while every socket is still held). Admission is counted
// from the servers and the engine, refusals only from ICMP, and anything
// else is delivery loss, kept apart: a lost datagram can neither pass for a
// refusal nor hide an admitted session the engine still lists.
type sessions struct {
	opened, answered, refused int
	gotOut                    int // sockets whose datagram reached a server
	listed                    int // UDP sessions the engine lists for the app
	unknown                   int // matched by the client's own local endpoint, never by its label
	refusedButOut             int // refused, yet the datagram got out anyway
	lostOut, lostBack         int // never reached a server and never refused; or reached one and never answered
}

func (s sessions) admitted() int   { return max(s.gotOut, s.listed) }
func (s sessions) identified() int { return max(s.gotOut-s.unknown, s.listed) }
func (s sessions) lost() int       { return s.lostOut + s.lostBack }

// floodSessions gathers the three sides while the floods still hold their
// sockets.
func (e *Env) floodSessions(names []string, results map[string]app.FloodResult) map[string]sessions {
	listed := map[string]int{}
	bySource := map[string]engine.Flow{}
	for _, f := range e.Flows() {
		if f.Protocol == "udp" {
			listed[f.App]++
			bySource[f.Source.String()] = f
		}
	}
	recs := e.Records()
	out := map[string]sessions{}
	for _, name := range names {
		r := results[name]
		seen := map[int]bool{}
		serverLine := map[int]engine.LineID{}
		for _, rec := range Select(recs, Tagged("udp", r.Token)) {
			// "T:<token>:0:<socket> "
			fields := strings.Split(strings.TrimSpace(rec.Data), ":")
			if i, err := strconv.Atoi(fields[len(fields)-1]); err == nil {
				seen[i] = true
				serverLine[i] = topo.LineOfText(rec.Src)
			}
		}
		s := sessions{opened: r.Opened, answered: r.Answered, refused: r.Refused, gotOut: len(seen), listed: listed[AppPath(name)]}
		if _, ok := e.Eng.(engine.V1); ok {
			e.T.Require(len(r.Locals) == r.Opened, "%s reports every local UDP endpoint (%d of %d)", name, len(r.Locals), r.Opened)
			unique := map[string]bool{}
			bad := 0
			for i, local := range r.Locals {
				unique[local] = true
				if f, ok := bySource[local]; ok {
					if f.App == "" {
						s.unknown++
						if f.AppID != "" || f.PID != 0 || f.Line != "a" || !seen[i] || serverLine[i] != "a" {
							bad++
						}
					} else {
						want := e.loadLine(name)
						if f.App != AppPath(name) || f.AppID != AppPath(name) || f.PID == 0 || f.Line != want || f.Lane != want || (seen[i] && serverLine[i] != want) {
							bad++
						}
					}
				}
			}
			e.T.Check(len(unique) == r.Opened && bad == 0, "%s's UDP endpoints match their own identified or unknown sessions (%d unique, %d unknown, %d invalid)", name, len(unique), s.unknown, bad)
		}
		for _, i := range r.RefusedSockets {
			if seen[i] {
				s.refusedButOut++
			}
		}
		s.lostOut = r.Opened - s.gotOut - (s.refused - s.refusedButOut)
		s.lostBack = s.gotOut - r.Answered
		out[name] = s
	}
	return out
}

// checkSessions makes the mandatory checks on every app's flood: no refused
// session got out, and delivery loss stays small enough that the admission
// counts mean something.
func (e *Env) checkSessions(names []string, all map[string]sessions) {
	refusedButOut, lost, opened := 0, 0, 0
	for _, name := range names {
		s := all[name]
		refusedButOut += s.refusedButOut
		lost += s.lost()
		opened += s.opened
	}
	e.T.Check(refusedButOut == 0, "no session the engine refused got its datagram out (%d did; %s)", refusedButOut, describeSessions(names, all))
	e.T.Check(lost*50 <= opened, "delivery loss, counted apart from admission and refusal, stays within 2%% (%d of %d; %s)", lost, opened, describeSessions(names, all))
}

func describeSessions(names []string, all map[string]sessions) string {
	var parts []string
	for _, name := range names {
		s := all[name]
		parts = append(parts, fmt.Sprintf("%s: %d reached servers, engine lists %d identified and %d unknown, %d refused, %d lost out, %d replies lost", name, s.gotOut, s.listed, s.unknown, s.refused, s.lostOut, s.lostBack))
	}
	return strings.Join(parts, "; ")
}

// keptOpen is the mandatory half of "other traffic carries on" under
// overload: charlie's stream, open before it, was never closed and every
// answer came over its line. How long it may go quiet belongs with the
// limits in each case's defect assertion: without admission control an
// overloaded engine stalls other flows (the baseline went 3.2 s without an
// answer under 9,000 handshakes at once).
func (e *Env) keptOpen(label string, s Stream, want engine.LineID) {
	if e.deferAttribution {
		e.T.Logf("%s: original survival-and-all-on-%s check would pass: %t", label, want,
			s.Connected && s.ClosedAt == 0 && s.Pongs > 0 && StreamLines(s)[want] == s.Pongs)
	}
	want = e.streamLine(s, want)
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
	all := e.floodSessions(names, results)
	e.checkSessions(names, all)
	least, most, total, fewestRefused, totalUnknown := perApp, 0, 0, perApp, 0
	refusalsEnough := true
	for _, name := range names {
		s := all[name]
		least, most, total = min(least, s.gotOut-s.unknown), max(most, s.identified()), total+s.admitted()
		fewestRefused = min(fewestRefused, s.refused)
		totalUnknown += s.unknown
		refusalsEnough = refusalsEnough && s.refused >= max(0, perApp-udpSessionsPerApp-s.unknown)*9/10
		if _, ok := e.Eng.(engine.V1); ok {
			e.T.Check(s.listed >= udpSessionsPerApp, "identified %s sessions actually fill their %d-session cap (%d)", name, udpSessionsPerApp, s.listed)
		}
	}
	e.T.Check(totalUnknown <= 512, "unknown UDP sessions remain in their separate 512-session pool (%d)", totalUnknown)
	e.T.Check(total < udpSessionsTotal*3/4, "the two apps together stay far from the total limit (%d admitted)", total)
	e.checkLoadIdentity(least >= udpSessionsPerApp*95/100, "each app still got at least 95%% of its allowed %d identified sessions out to the servers (least %d; %s)", udpSessionsPerApp, least, describeSessions(names, all))
	e.holding(bgs, release)
	var s Stream
	stream.WaitJSON(e, 30*time.Second, &s)
	e.keptOpen("charlie's stream through the flood", s, "c")
	e.T.Check(e.Eng.Running(), "the engine is still running")
	excess := perApp - udpSessionsPerApp
	e.T.Expect(most <= udpSessionsPerApp && refusalsEnough && responsive(s),
		"no identified app has more than %d sessions and its %d extra attempts, apart from explicitly counted unknown admissions, are refused, while charlie stays responsive (most identified %d, fewest refused %d, longest silence %d ms; %s)",
		udpSessionsPerApp, excess, most, fewestRefused, s.MaxGapMS, describeSessions(names, all))
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
	all := e.floodSessions(names, results)
	e.checkSessions(names, all)
	gotOut, listed, refused := 0, 0, 0
	for _, name := range names {
		gotOut += all[name].gotOut
		listed += all[name].listed
		refused += all[name].refused
	}
	// 1.0 also counts its live UDP sessions itself.
	if v1, ok := e.Eng.(engine.V1); ok && v1.Session() != nil {
		st, err := v1.Session().Stats(e.Ctx())
		e.T.Require(err == nil, "stats while the sessions are held (%v)", err)
		listed = max(listed, int(st.UDP))
	}
	admitted := max(gotOut, listed)
	e.T.Check(gotOut >= udpSessionsTotal*95/100, "together the apps still got at least 95%% of the %d sessions allowed in total out to the servers (%d; %s)", udpSessionsTotal, gotOut, describeSessions(names, all))
	e.holding(bgs, release)
	var s Stream
	stream.WaitJSON(e, 30*time.Second, &s)
	e.keptOpen("charlie's stream through the flood", s, "c")
	e.T.Check(e.Eng.Running(), "the engine is still running")
	asked := perApp * len(names)
	excess := asked - udpSessionsTotal
	e.T.Expect(admitted <= udpSessionsTotal && refused >= excess*9/10 && responsive(s),
		"all together no more than %d of the %d sessions are admitted, by the servers or the engine, and the %d extra are refused, while charlie's stream never waits 2 s for an answer (%d reached servers, engine lists %d, %d refused, longest silence %d ms; %s)",
		udpSessionsTotal, asked, excess, gotOut, listed, refused, s.MaxGapMS, describeSessions(names, all))
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
	from := e.Mark()
	hold := e.Start(Run{App: "bravo", Args: append([]string{"tcphold", "--to", floodTargets(0, wire.PortHold), "--count", strconv.Itoa(storm),
		"--concurrency", "300", "--timeout", "5000"}, release.Arg()...)})
	hold.WaitLine(e, "holding ", 3*time.Minute)
	e.ExpectTCP("foxtrot during the storm", "foxtrot", AsUser, "a", topo.Server4, 3)
	e.T.Check(hold.Running(), "bravo still holds its connections")
	known, unknown := 0, 0
	_, v10 := e.Eng.(engine.V1)
	if v10 {
		bad := 0
		for _, flow := range e.Flows() {
			if flow.Protocol != "tcp" || flow.Destination.Port() != wire.PortHold {
				continue
			}
			if flow.App == "" {
				unknown++
				if flow.Line != "a" {
					bad++
				}
			} else {
				known++
				if flow.App != AppPath("bravo") || flow.Line != "b" {
					bad++
				}
			}
		}
		e.T.Check(bad == 0 && unknown <= 2048, "held identities use their correct lanes and unknown stays bounded (%d known, %d unknown, %d invalid)", known, unknown, bad)
		// Unknown flows are a separate pool on the main lane (5.4). The
		// known app must actually reach its limit for this case to prove it.
		e.T.Check(known >= tcpFlowsPerApp, "identified bravo connections reach the %d per-app limit (%d)", tcpFlowsPerApp, known)
	}
	release.Open(e)
	var r app.HoldResult
	hold.WaitJSON(e, time.Minute, &r)
	refused := r.Errors["ECONNREFUSED"] + r.Errors["ECONNRESET"]
	if !v10 {
		known = r.Established
	} else {
		e.T.Check(known+unknown == r.Established, "the client's held connections match the identified and unknown pools (%d = %d + %d)", r.Established, known, unknown)
		isHold := func(record inet.Record) bool {
			return record.Kind == "tcp" && record.T >= from && strings.HasSuffix(record.Dst, ":"+strconv.Itoa(wire.PortHold))
		}
		recs, _ := e.WaitRecords(10*time.Second, func(records []inet.Record) bool { return len(Select(records, isHold)) >= r.Established })
		accepted := Select(recs, isHold)
		lines := RecordLines(accepted)
		e.T.Check(len(accepted) == r.Established && lines["b"] == known && lines["a"] == unknown, "servers independently confirm both pools on their required lines (%s)", Describe(lines))
	}
	e.checkLoadIdentity(known >= tcpFlowsPerApp*95/100, "identified bravo still got at least 95%% of its allowed %d connections (%d identified, %d unknown, errors %v)", tcpFlowsPerApp, known, unknown, r.Errors)
	e.T.Check(r.StillOpen == r.Established, "admitted connections stay open (%d of %d)", r.StillOpen, r.Established)
	var s Stream
	stream.WaitJSON(e, 30*time.Second, &s)
	e.keptOpen("charlie's stream through the storm", s, "c")
	e.T.Check(e.Eng.Running(), "the engine is still running")
	e.T.Expect(known <= tcpFlowsPerApp && refused == storm-r.Established && refused > 0 && r.FailedMS.Max < 3000 && responsive(s),
		"the identified app stays within %d, the separately counted unknown pool is bounded, and every other attempt is refused within 3 s while charlie stays responsive (%d identified, %d unknown, %d refused; slowest refusal %.0f ms, longest silence %d ms)",
		tcpFlowsPerApp, known, unknown, refused, r.FailedMS.Max, s.MaxGapMS)
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
	var baseline engine.Stats
	if v1, ok := e.Eng.(engine.V1); ok {
		baseline = stats(e, v1.Session())
	}
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
	unknown := 0
	if v1, ok := e.Eng.(engine.V1); ok {
		if profiler, ok := e.Eng.(interface{ CaptureProfiles(context.Context) error }); ok {
			ctx, cancel := context.WithTimeout(e.Ctx(), 15*time.Second)
			err := profiler.CaptureProfiles(ctx)
			cancel()
			e.T.Check(err == nil, "heap and goroutine profiles captured while the flows remain held (%v)", err)
		}
		st, err := v1.Session().Stats(e.Ctx())
		e.T.Require(err == nil, "stats while all TCP flows are held (%v)", err)
		unknown = int(st.Unknown)
		e.T.Check(unknown <= 2048 && st.PeakUnknown <= 2048, "unknown TCP admission never exceeds its separate 2048-flow budget (%d held, %d peak)", unknown, st.PeakUnknown)
		// Server hold records exclude the separate survival stream. Its
		// identity was captured before the load, so keep both counts aligned.
		for _, f := range e.streamFlows {
			if f.App == "" {
				unknown--
			}
		}
		e.T.Check(unknown >= 0, "held unknown flows exclude only the observed survival stream (%d)", unknown)
		e.T.Logf("held TCP flows: %d; runtime memory and queues: %v", established, st.Counters)
		if st.Flows > 0 {
			e.T.Logf("CAP MEMORY: flows=%d heap=%d stack=%d runtime=%d heap/flow=%d stack/flow=%d incremental-heap/flow=%d GC-CPU-ppm=%d GC-CPU-ns=%d total-CPU-ns=%d goroutines=%d starting-stack=%d tun=%s output-drops=%d", st.Flows, st.Counters["heapBytes"], st.Counters["stackBytes"], st.Counters["runtimeBytes"], st.Counters["heapBytes"]/uint64(st.Flows), st.Counters["stackBytes"]/uint64(st.Flows), (st.Counters["heapBytes"]-baseline.Counters["heapBytes"])/uint64(st.Flows), st.Counters["gcCPUppm"], st.Counters["gcCPUNanos"]-baseline.Counters["gcCPUNanos"], st.Counters["totalCPUNanos"]-baseline.Counters["totalCPUNanos"], st.Counters["goroutines"], st.Counters["stackStartBytes"], st.TunKernel, st.Counters["tunDropped"])
		}
		e.T.Check(st.Flows == tcpFlowsTotal, "the cap profile measures all %d live flows (%d)", tcpFlowsTotal, st.Flows)
	}
	lines := RecordLines(accepted)
	e.T.Check(len(accepted) == established && lines["c"] == established-unknown && lines["a"] == unknown,
		"servers confirm every held connection: identified flows on c, unknown flows on the main lane a (%d held, %d unknown; lines %s)", established, unknown, Describe(lines))
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
	exerciseTCPBufferBudget(e, s)
}

func exerciseTCPBufferBudget(e *Env, s engine.Controller) {
	// A download's send buffer toward the app grows from the 64 KiB floor to
	// at most 6 MiB, doubling only in a 250 ms tick in which the flow moved at
	// least its current buffer, and the grant stays while bytes keep moving
	// (internal/engine/tcp/buffers.go). So each flow gets 3.5 s at full speed,
	// four flows at a time, then a byte every 100 ms: 64 flows that each earn
	// the full 5.94 MiB of growth want 380 MiB at once, half again the 256 MiB
	// budget (5.9), and keep wanting it. Only the budget can refuse them.
	const flows, perWave, burstMS = 64, 4, 3500
	const maxGrowth = int64(6<<20 - 64<<10)
	release := e.NewRelease("buffers")
	var bgs []*Bg
	for i := range flows {
		delay := (i / perWave) * burstMS
		bgs = append(bgs, e.Start(Run{App: "charlie", Args: append([]string{"bulkhold", "--to", To(topo.Server4, wire.PortBulk),
			"--flood", strconv.Itoa(burstMS), "--delay", strconv.Itoa(delay)}, release.Arg()...)}))
	}
	ramp := time.Duration(flows/perWave*burstMS)*time.Millisecond + 3*time.Second
	most, samples := int64(0), 0
	var held []int64
	var previousDrops, previousRTO, previousRecovery uint64
	for start := time.Now(); time.Since(start) < ramp+3*time.Second && e.Ctx().Err() == nil; {
		st, err := s.Stats(e.Ctx())
		e.T.Require(err == nil, "stats while the downloads run (%v)", err)
		most = max(most, st.TCPBytes)
		if drops, rto, recovery := st.Counters["tunDropped"], st.Counters["tcpRTOs"], st.Counters["tcpSACKRecoveries"]; drops != previousDrops || rto != previousRTO || recovery != previousRecovery {
			e.T.Logf("TCP loss at %.3f s: outputDrops=%d transportDrops=%d retransmits=%d RTO=%d SACK=%d heap=%d GC=%d", time.Since(start).Seconds(), drops, st.Counters["transportDropped"], st.Counters["tcpRetransmits"], rto, recovery, st.Counters["heapBytes"], st.Counters["gcCycles"])
			previousDrops, previousRTO, previousRecovery = drops, rto, recovery
		}
		samples++
		if time.Since(start) >= ramp {
			held = append(held, st.TCPBytes)
		}
		e.Sleep(100 * time.Millisecond)
	}
	release.Open(e)
	intact, open, earned := 0, 0, 0
	endStats := stats(e, s)
	e.T.Logf("TCP growth workload: lookups=%d misses=%d owners=%s counters=%v", endStats.LookupCount, endStats.LookupMisses, endStats.OwnerLookup, endStats.Counters)
	for i, bg := range bgs {
		var r app.BulkHoldResult
		bg.WaitJSON(e, time.Minute, &r)
		if r.Intact {
			intact++
		}
		if r.Open {
			open++
		}
		steady := steadyMS(r.Bins, r.BinMS, earnWindowBins, earnPerWindow)
		if steady >= earnSteadyMS {
			earned++
		} else {
			e.T.Logf("download %d did not earn growth: steady=%d ms burstBytes=%d totalBytes=%d error=%q bins=%v", i, steady, r.BurstBytes, r.Bytes, r.Err, r.Bins)
		}
	}
	least := most
	for _, b := range held {
		least = min(least, b)
	}
	e.T.Check(intact == flows && open == flows, "all %d downloads arrived intact, every byte checked, and were open until released (%d intact, %d open)", flows, intact, open)
	// A prerequisite: without the demand, a budget that's never reached
	// proves nothing about the budget.
	e.T.Require(earned == flows, "every download kept up 5 MiB in every 200 ms for 2 s of its burst, enough to earn the full 6 MiB buffer, so together they wanted %.0f MiB (%d of %d did)",
		float64(flows*maxGrowth)/(1<<20), earned, flows)
	e.T.Check(most <= tcpBufferBudget, "buffer growth never went over the %d MiB budget (most %.1f MiB over %d samples)", tcpBufferBudget>>20, float64(most)/(1<<20), samples)
	e.T.Check(len(held) > 0 && least >= tcpBufferBudget-maxGrowth,
		"once every flow had asked, growth filled the budget to within one flow's grant and stayed there, so the rest was refused (least %.1f MiB over %d samples, most %.1f MiB)",
		float64(least)/(1<<20), len(held), float64(most)/(1<<20))
}

// Steady demand that earns a flow the full send buffer. The engine doubles a
// flow's buffer in a 250 ms tick only if the flow moved at least the current
// buffer in it, and the last doubling (4 MiB to the 6 MiB cap) needs 4 MiB in
// one tick. Any 250 ms tick holds four whole 50 ms bins, so when every four
// bins in a row carry 5 MiB (4 MiB and a margin for the bytes in flight),
// every tick inside that stretch qualifies, whatever the two clocks'
// alignment; 2 s of it holds at least seven whole ticks, the seven doublings
// from 64 KiB to the cap.
const (
	earnWindowBins = 4
	earnPerWindow  = 5 << 20
	earnSteadyMS   = 2000
)

// steadyMS is the longest stretch, in ms, over which every run of window
// bins in a row carried at least least bytes.
func steadyMS(bins []int64, binMS, window int, least int64) int {
	best, run := 0, 0
	for j := 0; j+window <= len(bins); j++ {
		sum := int64(0)
		for _, b := range bins[j : j+window] {
			sum += b
		}
		if sum >= least {
			run++
		} else {
			run = 0
		}
		best = max(best, run)
	}
	if best == 0 {
		return 0
	}
	return (best + window - 1) * binMS
}

// cappedFloods runs apps pinned to a blocked line, each opening sockets new
// UDP sessions at rate a second for long enough to cover several whole
// seconds, and checks what doesn't depend on the limits: every socket opened
// and sent, at the rate asked (a slow sender would fake a limit), nothing
// got out, nothing was answered, and the notices held back were counted.
// It returns refusals and sends per app per Unix second (the engine's
// limiters count by the same clock), and the seconds in which every app was
// sending throughout.
func (e *Env) cappedFloods(names []string, sockets, rate int) (refusals, sends map[string]map[int64]int, whole []int64) {
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
	from := e.Mark()
	bgs := map[string]*Bg{}
	for i, name := range names {
		bgs[name] = e.Start(Run{App: name, Args: []string{"udpflood", "--to", floodTargets(i, wire.PortUDPEcho), "--sockets", strconv.Itoa(sockets),
			"--rate", strconv.Itoa(rate), "--timeout", "2000", "--times"}})
	}
	refusals, sends = map[string]map[int64]int{}, map[string]map[int64]int{}
	var firstWhole, lastWhole int64 // the whole seconds every app sent through
	sent, refused, answered := 0, 0, 0
	for i, name := range names {
		var r app.FloodResult
		bgs[name].WaitJSON(e, 2*time.Minute, &r)
		// A flood that didn't open, send or keep its rate measures nothing:
		// that stops the case as a failed prerequisite.
		e.T.Require(r.Opened == sockets && r.Sent == sockets && len(r.OpenErrors) == 0 && len(r.SendErrors) == 0 && len(r.SentAt) == sockets,
			"capped %s opened %d sockets and sent on each (%d opened, %d sent, %d send times, errors %v %v)", name, sockets, r.Opened, r.Sent, len(r.SentAt), r.OpenErrors, r.SendErrors)
		first, last := r.SentAt[0], r.SentAt[len(r.SentAt)-1]
		span := float64(last-first) / 1000
		e.T.Require(span > 0 && float64(sockets)/span >= float64(rate)*9/10,
			"capped %s sent at %d a second or more (%d over %.2f s)", name, rate*9/10, sockets, span)
		refusals[name], sends[name] = map[int64]int{}, map[int64]int{}
		for _, t := range r.RefusedAt {
			refusals[name][t/1000]++
		}
		for _, t := range r.SentAt {
			sends[name][t/1000]++
		}
		if i == 0 {
			firstWhole, lastWhole = first/1000+1, last/1000-1
		} else {
			firstWhole, lastWhole = max(firstWhole, first/1000+1), min(lastWhole, last/1000-1)
		}
		answered += r.Answered
		sent += r.Sent
		refused += r.Refused
	}
	// The window comes from send times the apps really recorded; check it
	// before walking it.
	e.T.Require(lastWhole-firstWhole >= 1 && lastWhole-firstWhole < 60,
		"the apps were all sending through at least two whole seconds, and fewer than 60 (seconds %d to %d)", firstWhole, lastWhole)
	for sec := firstWhole; sec <= lastWhole; sec++ {
		whole = append(whole, sec)
	}
	e.Sleep(500 * time.Millisecond)
	escaped := Select(e.Records(), func(r inet.Record) bool { return r.Kind == "udp" && r.T >= from })
	after, err := s.Stats(e.Ctx())
	e.T.Require(err == nil, "stats (%v)", err)
	unknown := after.AdmittedUnknownUDP - before.AdmittedUnknownUDP
	admitted := after.Admitted - before.Admitted
	e.T.Require(unknown <= uint64(sent), "unknown admission counter stays within actual sends (%d of %d)", unknown, sent)
	e.T.Check(admitted == unknown && after.PeakUnknownUDP <= 512, "no identified capped flow was admitted; unknown flows obey their separate pool (%d admitted, %d unknown, %d peak unknown UDP)", admitted, unknown, after.PeakUnknownUDP)
	e.T.Check(uint64(len(escaped)) == unknown && RecordLines(escaped)["a"] == len(escaped) && answered == len(escaped), "server records and replies account for exactly the unknown flows allowed on the main lane (%d recorded, %d answered, %d unknown; lines %s)", len(escaped), answered, unknown, Describe(RecordLines(escaped)))
	e.T.Require(refused+int(unknown) <= sent, "allowed and refused sessions are disjoint (%d allowed, %d refused, %d sent)", unknown, refused, sent)
	dropped := after.DroppedNotices - before.DroppedNotices
	e.T.Check(dropped >= uint64(sent-int(unknown)-refused)*9/10, "the notices held back for rejected sessions were counted (%d sessions, %d allowed unknown, %d told, %d counted as dropped)", sent, unknown, refused, dropped)
	return refusals, sends, whole
}

func rejectionNoticesPerApp(e *Env) {
	// One app alone, three times its own budget and well under the total's:
	// only the per-app limiter can hold it to about 1,000 a second.
	refusals, sends, whole := e.cappedFloods([]string{"alpha"}, 12000, 3000)
	worst := 0
	for _, n := range refusals["alpha"] {
		worst = max(worst, n)
	}
	// A notice sent just before a second ends can arrive just after it.
	e.T.Check(worst <= noticesPerApp*105/100, "alpha got no more than %d refusal notices in any second (most %d, per second %v)", noticesPerApp, worst, refusals["alpha"])
	var low []string
	for _, sec := range whole {
		if sends["alpha"][sec] < 2500 || refusals["alpha"][sec] < noticesPerApp*9/10 {
			low = append(low, fmt.Sprintf("%d: %d sent, %d told", sec, sends["alpha"][sec], refusals["alpha"][sec]))
		}
	}
	e.T.Check(len(low) == 0, "in every whole second alpha sent at least 2,500 and was told about 1,000 times (short: %s)", strings.Join(low, "; "))
}

func rejectionNoticesTotal(e *Env) {
	// Eight apps, each under its own budget at 800 a second: 6,400 a second
	// together, so only the total limiter can hold them to about 5,000.
	names := []string{"alpha", "bravo", "delta", "foxtrot", "golf", "hotel", "india", "juliett"}
	refusals, sends, whole := e.cappedFloods(names, 3200, 800)
	total := map[int64]int{}
	for _, name := range names {
		for sec, n := range refusals[name] {
			total[sec] += n
		}
	}
	worst := 0
	for _, n := range total {
		worst = max(worst, n)
	}
	e.T.Check(worst <= noticesTotal*105/100, "together the apps got no more than %d refusal notices in any second (most %d, per second %v)", noticesTotal, worst, total)
	var low []string
	for _, sec := range whole {
		sent := 0
		for _, name := range names {
			sent += sends[name][sec]
		}
		if sent < 6000 || total[sec] < noticesTotal*9/10 {
			low = append(low, fmt.Sprintf("%d: %d sent, %d told", sec, sent, total[sec]))
		}
	}
	e.T.Check(len(low) == 0, "in every whole second the apps sent at least 6,000 together and were told about 5,000 times (short: %s)", strings.Join(low, "; "))
}

func timeWaitCap(e *Env) {
	e.StartEngine(e.DefaultConfig())
	_, s := e.v1()
	before, err := s.Stats(e.Ctx())
	e.T.Require(err == nil, "stats (%v)", err)
	// The whoami server closes first, so the engine's end toward the app is
	// the one that waits. 5,000 closings at about 330 a second all fall
	// inside the 60 s wait: 4,096 fill the cap and the rest must skip it.
	const n, timeWaitLimit = 5000, 4096
	bg := e.Start(Run{App: "alpha", Args: []string{"tcp", "--to", To(topo.Server4, wire.PortWhoami), "--count", strconv.Itoa(n),
		"--concurrency", "4", "--gap", "10", "--timeout", "5000", "--port-base", strconv.Itoa(e.ports(n))}})
	peak := int64(0)
	for bg.Running() && e.Ctx().Err() == nil {
		st, err := s.Stats(e.Ctx())
		e.T.Require(err == nil, "stats during the connections (%v)", err)
		peak = max(peak, st.TimeWait)
		e.Sleep(200 * time.Millisecond)
	}
	var r app.TCPResult
	bg.WaitJSON(e, time.Minute, &r)
	after, err := s.Stats(e.Ctx())
	e.T.Require(err == nil, "stats (%v)", err)
	peak = max(peak, after.TimeWait)
	e.T.Check(r.OK == n, "all %d connections succeeded: TIME_WAIT never refuses a new one (%d, errors %v)", n, r.OK, r.Errors)
	e.T.Check(peak <= timeWaitLimit && peak >= timeWaitLimit*95/100, "TIME_WAIT filled its own cap of %d and never went over it (most %d)", timeWaitLimit, peak)
	skipped := after.TimeWaitSkipped - before.TimeWaitSkipped
	e.T.Check(skipped >= uint64(n-timeWaitLimit)*9/10, "closings past the cap skipped TIME_WAIT, counted (%d skipped)", skipped)
	var live []string
	for _, f := range e.Flows() {
		if f.App == AppPath("alpha") {
			live = append(live, f.Protocol+" "+f.Source.String()+" -> "+f.Destination.String())
		}
	}
	e.T.Check(len(live) == 0 && after.Flows <= 2, "waiting endpoints aren't live flows: none of alpha's is listed and the engine counts %d flows beside %d waiting (%s)",
		after.Flows, after.TimeWait, strings.Join(upTo(live, 3), "; "))
	e.ExpectTCP("alpha's new connections with TIME_WAIT full", "alpha", AsUser, "a", topo.Server4, 50)
	e.ExpectTCP("bravo's new connections with TIME_WAIT full", "bravo", AsUser, "b", topo.Server4, 10)
}
