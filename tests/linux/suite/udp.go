//go:build linux

package suite

import (
	"fmt"
	"strings"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/app"
	"github.com/AyoubAchour/net-switch/tests/linux/engine"
	"github.com/AyoubAchour/net-switch/tests/linux/harness"
	"github.com/AyoubAchour/net-switch/tests/linux/inet"
	"github.com/AyoubAchour/net-switch/tests/linux/topo"
	"github.com/AyoubAchour/net-switch/tests/linux/wire"
)

func init() { register(30, addUDP) }

func addUDP(r *registry) {
	r.add("udp.stun-same-mapping", "STUN from one socket to two servers sees the same public address and port", harness.Parity, "5.3", 0, stunSameMapping)
	r.add("udp.unsolicited-reply", "A reply from a host the app never contacted reaches it, from that host (endpoint-independent filtering)", harness.Parity, "5.3", 0, unsolicitedReply)
	r.add("udp.fifty-destinations-one-session", "First datagrams to 50 destinations at once from one socket make one session with one public endpoint", harness.Parity, "5.3", 0, fiftyDestinations)
	r.defect("udp.port-reuse-under-traffic", "Another app reusing a UDP port under continuous traffic gets its own line within 1 s",
		"the UDP session is keyed by source port only, so the next app inherits the previous app's line", "5.3", 0,
		func(e *Env) { udpPortReuse(e, false) })
	r.defect("udp.port-reuse-to-blocked-line", "Another app reusing a UDP port, pinned to a blocked line, is refused within 1 s and nothing gets out",
		"the next app inherits the previous app's session, so its datagrams go out and it's never refused", "4.6, 5.3", 0,
		func(e *Env) { udpPortReuse(e, true) })
	r.add("caps.blocked-udp-rejected-fast", "A capped app sending UDP non-stop keeps getting refused, and nothing gets out", harness.Parity, "4.6, 5.3, 5.9", 0, cappedUDP)
	r.defect("caps.blocked-tcp-fails-fast", "A capped app's new connections are refused at once, every time, and none reaches the internet",
		"the cap's reject rule has no no_drop: after 50 refusals in 30 s sing-box drops instead, and connections hang (the cap hang)", "4.6, 5.4", 0, cappedTCP)
	r.defect("tcp.port-reuse-freeze", "Reusing a TCP source port right after a connection closes never stalls, with exactly one dial each time",
		"gVisor keeps the closed connection in TIME_WAIT for 60 s and drops a new SYN on its 4-tuple (the 60 s freeze)", "5.1", 3*time.Minute, tcpPortReuse)
}

func stunSameMapping(e *Env) {
	e.StartEngine(e.DefaultConfig())
	// charlie is on line c, which isn't NATed: what the servers see is the
	// engine's own socket.
	var r app.STUNResult
	servers := To(topo.Server4, wire.PortSTUN1) + "," + To(topo.Server4b, wire.PortSTUN2)
	e.RunJSON(Run{App: "charlie", Args: []string{"stun", "--servers", servers}}, &r)
	a, b := r.Mapped[To(topo.Server4, wire.PortSTUN1)], r.Mapped[To(topo.Server4b, wire.PortSTUN2)]
	e.T.Require(a != "" && b != "", "both STUN servers answered (%v, errors %v)", r.Mapped, r.Errors)
	e.T.Check(topo.LineOfText(a) == "c", "the mapping is on charlie's line c (%s)", a)
	e.T.Check(a == b, "both servers saw the same public address and port: %s and %s", a, b)
}

func unsolicitedReply(e *Env) {
	e.StartEngine(e.DefaultConfig())
	var r app.STUNResult
	e.RunJSON(Run{App: "charlie", Args: []string{"stun", "--servers", To(topo.Server4, wire.PortSTUN1), "--poke", To(topo.Server4, wire.PortPoke), "--wait", "3000"}}, &r)
	e.T.Require(r.Acked, "the poke server answered (%v)", r.Errors)
	third := To(topo.Third4, wire.PortPokeSrc)
	e.T.Check(r.Poked && r.PokeFrom == third, "a datagram from %s, which charlie never contacted, reached it from that address (arrived %v, from %q)", third, r.Poked, r.PokeFrom)
}

func fiftyDestinations(e *Env) {
	e.StartEngine(e.DefaultConfig())
	// Many open files make owner lookup slow on purpose, so all 50 first
	// datagrams reach the engine while it's still deciding the new session.
	holder := e.Start(Run{App: "alpha", Args: []string{"holdfiles", "--count", "10000"}})
	holder.WaitOutput(e, "{\"holding\"", 30*time.Second)
	var dests []string
	for _, addr := range topo.ManyServers() {
		dests = append(dests, To(addr, wire.PortUDPEcho))
	}
	// charlie keeps its socket open until every check below is done: an
	// engine that drops a session as soon as its socket closes (5.3's destroy
	// notifications) would otherwise list none by the time they're counted.
	release := e.NewRelease("burst")
	burst := e.Start(Run{App: "charlie", Args: append([]string{"udpburst", "--to", strings.Join(dests, ","), "--wait", "5000"}, release.Arg()...)})
	var r app.BurstResult
	burst.WaitHeld(e, "", 30*time.Second, &r)
	holder.Stop()
	e.T.Require(r.Sent == 50 && len(r.SendErrors) == 0, "all 50 first datagrams were sent (%d, errors %v)", r.Sent, r.SendErrors)
	e.T.Check(r.SpreadMS < 5, "they left within %.2f ms of each other (at once: under 5 ms)", r.SpreadMS)
	answered := map[int]bool{}
	wrongSource, seen := 0, map[string]int{}
	for _, reply := range r.Replies {
		answered[reply.Index] = true
		if reply.Index < 0 || reply.Index >= len(r.To) || reply.From != r.To[reply.Index] {
			wrongSource++
		}
		seen[reply.Seen]++
	}
	e.T.Check(len(answered) == 50 && len(r.Replies) == 50, "each of the 50 destinations answered its own datagram once (%d distinct of %d replies)", len(answered), len(r.Replies))
	e.T.Check(wrongSource == 0, "every reply came from the destination it was sent to (%d didn't)", wrongSource)
	e.T.Check(len(seen) == 1 && topo.LineOfText(firstKeys(seen, 1)) == "c", "all 50 servers saw one public endpoint on line c (%d different: %s)", len(seen), firstKeys(seen, 4))
	recs, _ := e.WaitRecords(2*time.Second, func(recs []inet.Record) bool { return len(Select(recs, Tagged("udp", r.Token))) >= 50 })
	arrived := Select(recs, Tagged("udp", r.Token))
	dsts, srcs := map[string]bool{}, map[string]bool{}
	for _, rec := range arrived {
		dsts[rec.Dst], srcs[rec.Src] = true, true
	}
	e.T.Check(len(arrived) == 50 && len(dsts) == 50 && len(srcs) == 1, "the servers recorded 50 datagrams to 50 different addresses from one source (%d datagrams, %d addresses, %d sources)", len(arrived), len(dsts), len(srcs))
	e.T.Require(burst.Running(), "charlie still holds its socket while the sessions are counted")
	sessions := 0
	for _, f := range e.Flows() {
		if f.Protocol == "udp" && int(f.Source.Port()) == r.LocalPort {
			sessions++
		}
	}
	e.T.Check(sessions == 1, "the engine has exactly one UDP session for charlie's open socket (it lists %d)", sessions)
	release.Open(e)
	burst.Wait(e, 30*time.Second)
}

func firstKeys(m map[string]int, n int) string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
		if len(keys) == n {
			break
		}
	}
	return strings.Join(keys, ", ")
}

// udpPortReuse: bravo (line b) sends from a port non-stop, exits, and another
// app takes the same port at once. Its datagrams must get its own decision
// within 1 s (5.3's accepted window).
func udpPortReuse(e *Env, blocked bool) {
	cfg := e.DefaultConfig()
	second, want := "charlie", engine.LineID("c")
	if blocked {
		second = "delta"
		cfg.Policy.Pins = append(cfg.Policy.Pins, engine.Pin{App: e.App("delta"), Line: "c"})
		cfg.Policy.Blocked = []engine.LineID{"c"}
	}
	e.StartEngine(cfg)
	const port = "40123"
	target := To(topo.Server4, wire.PortUDPEcho)
	var first app.UDPStreamResult
	e.RunJSON(Run{App: "bravo", Args: []string{"udpstream", "--to", target, "--local-port", port, "--duration", "2000", "--rate", "50"}}, &first)
	firstLines := Lines(eventsSeen(first.Replies))
	e.T.Require(len(first.Replies) > 50 && firstLines["b"] == len(first.Replies), "bravo's stream from port %s used line b (%s)", port, Describe(firstLines))
	recorded := len(Select(e.Records(), Tagged("udp", first.Token)))
	e.T.Require(recorded > 50, "the server recorded bravo's datagrams (%d)", recorded)

	var next app.UDPStreamResult
	e.RunJSON(Run{App: second, Args: []string{"udpstream", "--to", target, "--local-port", port, "--duration", "3000", "--rate", "50", "--connect"}}, &next)
	e.T.Check(next.LocalPort == first.LocalPort && next.Sent >= 100, "%s sent %d datagrams from the same port %d", second, next.Sent, next.LocalPort)
	settle := next.StartedAt + 1000
	e.Sleep(500 * time.Millisecond)
	arrived := Select(e.Records(), Tagged("udp", next.Token))
	late := Select(arrived, func(r inet.Record) bool { return r.T >= settle })
	if !blocked {
		lines := RecordLines(late)
		e.T.Check(len(late) >= 50, "the server got %d of %s's datagrams after its first second", len(late), second)
		e.T.Expect(len(late) > 0 && lines[want] == len(late),
			"1 s after %s took the port, all its datagrams arrive over its own line %s (server saw lines %s)", second, want, Describe(lines))
		return
	}
	refused := 0
	for _, ev := range append(next.RecvErrors, next.SendErrors...) {
		if ev.What == "ECONNREFUSED" && ev.T >= settle {
			refused++
		}
	}
	e.T.Expect(len(late) == 0 && refused > 0,
		"1 s after %s (pinned to blocked line c) took the port, none of its datagrams gets out and it's refused (%d arrived at the server, ECONNREFUSED %d times)", second, len(late), refused)
}

func eventsSeen(events []app.Event) map[string]int {
	m := map[string]int{}
	for _, ev := range events {
		m[ev.What]++
	}
	return m
}

func cappedUDP(e *Env) {
	cfg := e.DefaultConfig()
	cfg.Policy.Blocked = []engine.LineID{"b"}
	e.StartEngine(cfg)
	// Positive control: an app on an open line is answered and recorded.
	control := e.UDP("charlie", AsUser, "--to", To(topo.Server4, wire.PortUDPEcho), "--count", "5")
	_, recorded := e.WaitRecords(2*time.Second, func(recs []inet.Record) bool { return len(Select(recs, Tagged("udp", control.Token))) == 5 })
	e.T.Require(control.Received == 5 && recorded, "charlie on an open line is answered (%d of 5) and recorded by the server (%v)", control.Received, recorded)
	var r app.UDPStreamResult
	e.RunJSON(Run{App: "bravo", Args: []string{"udpstream", "--to", To(topo.Server4, wire.PortUDPEcho), "--duration", "3000", "--rate", "100", "--connect"}}, &r)
	e.Sleep(500 * time.Millisecond)
	leaked := len(Select(e.Records(), Tagged("udp", r.Token)))
	e.T.Check(r.Sent >= 200 && leaked == 0 && len(r.Replies) == 0, "none of the capped app's %d datagrams got out (%d reached the server)", r.Sent, leaked)
	// Refusals must keep coming for as long as it sends, not stop after a
	// burst: count them per half second.
	windows := map[int64]int{}
	for _, ev := range append(r.RecvErrors, r.SendErrors...) {
		if ev.What == "ECONNREFUSED" {
			windows[(ev.T-r.StartedAt)/500]++
		}
	}
	var silent []string
	for w := int64(1); w < 6; w++ {
		if windows[w] == 0 {
			silent = append(silent, fmt.Sprintf("%.1f-%.1f s", float64(w)/2, float64(w+1)/2))
		}
	}
	e.T.Check(len(silent) == 0, "the capped app is refused throughout (no refusals in: %s; refusals per half second %v)", strings.Join(silent, ", "), windows)
}

func cappedTCP(e *Env) {
	cfg := e.DefaultConfig()
	cfg.Policy.Blocked = []engine.LineID{"b"}
	e.StartEngine(cfg)
	// Positive control: an app on an open line gets through, and the server
	// records each connection it accepts.
	since := time.Now().UnixMilli()
	e.ExpectTCP("charlie on an open line", "charlie", AsUser, "c", topo.Server4, 3)
	accepted := Select(e.Records(), FromLine("tcp", "c", wire.PortWhoami, since, 0))
	e.T.Require(len(accepted) == 3, "the server recorded charlie's 3 connections (%d)", len(accepted))
	from := e.Mark()
	r := e.TCP("bravo", AsUser, "--to", To(topo.Server4, wire.PortWhoami), "--count", "150", "--concurrency", "10", "--timeout", "3000")
	e.Sleep(500 * time.Millisecond)
	dialed := Select(e.Records(), func(rec inet.Record) bool { return rec.Kind == "tcp" && rec.T >= from })
	connected := 0
	for _, a := range r.Attempts {
		if a.Connected {
			connected++
		}
	}
	e.T.Check(r.OK == 0 && connected == 0 && len(dialed) == 0,
		"none of the capped app's 150 connections got through: none completed its handshake (%d), and the servers accepted none (%d)", connected, len(dialed))
	e.T.Expect(r.FailedMS.Max < 1000 && r.Errors["ECONNREFUSED"]+r.Errors["ECONNRESET"] == 150,
		"every one of the 150 was refused within 1 s (slowest %.0f ms, p95 %.0f ms; errors %v)", r.FailedMS.Max, r.FailedMS.P95, r.Errors)
}

func tcpPortReuse(e *Env) {
	e.StartEngine(e.DefaultConfig())
	target := To(topo.Server4, wire.PortWhoami)
	from := time.Now().UnixMilli()
	var spaced app.ReuseResult
	e.RunJSON(Run{App: "alpha", Args: []string{"reuse", "--to", target, "--local-port", "45123", "--gaps", "0,10,100,500,1000", "--count", "6", "--timeout", "3000", "--stall", "100"}, Timeout: 2 * time.Minute}, &spaced)
	var burst app.ReuseResult
	e.RunJSON(Run{App: "alpha", Args: []string{"reuse", "--to", target, "--local-port", "45124", "--gaps", "0", "--count", "1000", "--timeout", "3000", "--stall", "100", "--stop-after", "3"}, Timeout: 2 * time.Minute}, &burst)
	e.Sleep(500 * time.Millisecond)
	e.T.Require(len(spaced.Attempts) > 0 && spaced.Attempts[0].Err == "" && topo.LineOfText(spaced.Attempts[0].Seen) == "a",
		"the first connection from port 45123 works on line a (%s)", attempts(spaced.Attempts[:1]))
	succeeded, wrongLine := 0, 0
	for _, a := range append(append([]app.Attempt{}, spaced.Attempts...), burst.Attempts...) {
		if a.Err == "" {
			succeeded++
			if topo.LineOfText(a.Seen) != "a" {
				wrongLine++
			}
		}
	}
	dials := Select(e.Records(), FromLine("tcp", "a", wire.PortWhoami, from, 0))
	e.T.Check(wrongLine == 0 && len(dials) == succeeded,
		"each successful reuse was exactly one dial on line a (%d successes, %d connections accepted by the server, %d on another line)", succeeded, len(dials), wrongLine)
	e.T.Expect(spaced.Stalls == 0 && burst.Stalls == 0 && len(burst.Attempts) == 1000,
		"reuse after 0, 10, 100, 500 and 1000 ms, then 1,000 immediate reuses, each under 100 ms (spaced: %d stalls, slowest %.0f ms: %s; burst: %d done, %d stalls, slowest %.0f ms)",
		spaced.Stalls, spaced.MaxMS, attempts(spaced.Attempts), len(burst.Attempts), burst.Stalls, burst.MaxMS)
}

func attempts(list []app.Attempt) string {
	var parts []string
	for _, a := range list {
		what := string(topo.LineOfText(a.Seen))
		if a.Err != "" {
			what = a.Err
		}
		parts = append(parts, fmt.Sprintf("%s@%.0fms", what, a.TotalMS))
	}
	return strings.Join(parts, " ")
}
