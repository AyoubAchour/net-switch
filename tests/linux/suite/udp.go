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
	r.add("udp.unsolicited-reply", "A reply from a host the app never contacted reaches it (endpoint-independent filtering)", harness.Parity, "5.3", 0, unsolicitedReply)
	r.add("udp.fifty-destinations-one-mapping", "First datagrams to 50 destinations at once share one session and public port", harness.Parity, "5.3", 0, fiftyDestinations)
	r.add("udp.port-reuse-under-traffic", "Another app reusing a UDP port under continuous traffic gets its own line within 1 s", harness.BaselineDefect, "5.3", 0,
		func(e *Env) { udpPortReuse(e, false) })
	r.add("udp.port-reuse-to-blocked-line", "Another app reusing a UDP port, pinned to a blocked line, is refused within 1 s", harness.BaselineDefect, "4.6, 5.3", 0,
		func(e *Env) { udpPortReuse(e, true) })
	r.add("caps.blocked-udp-rejected-fast", "A capped app sending UDP non-stop keeps getting refused, and nothing gets out", harness.Parity, "4.6, 5.3, 5.9", 0, cappedUDP)
	r.add("caps.blocked-tcp-fails-fast", "A capped app's new connections are refused at once, every time", harness.BaselineDefect, "4.6, 5.4", 0, cappedTCP)
	r.add("tcp.port-reuse-freeze", "Reusing a TCP source port right after a connection closes never stalls (the 60 s freeze)", harness.BaselineDefect, "5.1", 3*time.Minute, tcpPortReuse)
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
	var dests []string
	for _, addr := range topo.ManyServers() {
		dests = append(dests, To(addr, wire.PortUDPEcho))
	}
	u := e.UDP("charlie", AsUser, "--to", strings.Join(dests, ","), "--count", "1", "--interval", "0", "--wait", "3000")
	e.T.Require(u.Received == 50, "all 50 destinations answered (%d, send errors %v)", u.Received, u.SendErrors)
	e.T.Check(len(u.Seen) == 1, "all 50 servers saw the same public address and port (%d different: %s)", len(u.Seen), firstKeys(u.Seen, 4))
	var ports []string
	for _, f := range e.Flows() {
		if f.Protocol == "udp" && f.App == AppPath("charlie") {
			ports = append(ports, f.Source.String())
		}
	}
	e.T.Note("the engine lists %d UDP flows for charlie's one socket", len(ports))
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

	var next app.UDPStreamResult
	e.RunJSON(Run{App: second, Args: []string{"udpstream", "--to", target, "--local-port", port, "--duration", "3000", "--rate", "50", "--connect"}}, &next)
	settle := next.StartedAt + 1000
	if !blocked {
		late := map[engine.LineID]int{}
		for _, ev := range next.Replies {
			if ev.T >= settle {
				id := topo.LineOfText(ev.What)
				if id == "" {
					id = "?"
				}
				late[id]++
			}
		}
		total := 0
		for _, n := range late {
			total += n
		}
		e.T.Check(total >= 50 && late[want] == total,
			"%s's datagrams from the same port, 1 s after it started, all on line %s (%s; %d replies in all)", second, want, Describe(late), len(next.Replies))
		return
	}
	// Blocked: nothing of the second app's reaches the server after the window,
	// and it's told so.
	recs, _ := inet.ReadRecords(e.Net.InetDir() + "/udp.jsonl")
	leaked := 0
	for _, rec := range recs {
		if strings.HasPrefix(rec.Data, "T:"+next.Token+":") && rec.T >= settle {
			leaked++
		}
	}
	refused := 0
	for _, ev := range append(next.RecvErrors, next.SendErrors...) {
		if ev.What == "ECONNREFUSED" && ev.T >= settle {
			refused++
		}
	}
	e.T.Check(leaked == 0, "none of %s's datagrams reached the server 1 s after it took the port (%d did)", second, leaked)
	e.T.Check(refused > 0, "%s is refused (ECONNREFUSED %d times after the first second)", second, refused)
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
	var r app.UDPStreamResult
	e.RunJSON(Run{App: "bravo", Args: []string{"udpstream", "--to", To(topo.Server4, wire.PortUDPEcho), "--duration", "3000", "--rate", "100", "--connect"}}, &r)
	recs, _ := inet.ReadRecords(e.Net.InetDir() + "/udp.jsonl")
	leaked := 0
	for _, rec := range recs {
		if strings.HasPrefix(rec.Data, "T:"+r.Token+":") {
			leaked++
		}
	}
	e.T.Check(leaked == 0 && len(r.Replies) == 0, "none of the capped app's %d datagrams got out (%d reached the server)", r.Sent, leaked)
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
	r := e.TCP("bravo", AsUser, "--to", To(topo.Server4, wire.PortWhoami), "--count", "150", "--concurrency", "10", "--timeout", "3000")
	e.T.Check(r.OK == 0, "none of the capped app's 150 connections got through (%d did)", r.OK)
	e.T.Check(r.FailedMS.Max < 1000, "every refusal came within 1 s (slowest %.0f ms, p95 %.0f ms; errors %v)", r.FailedMS.Max, r.FailedMS.P95, r.Errors)
	e.ExpectTCP("charlie on an open line is unaffected", "charlie", AsUser, "c", topo.Server4, 3)
}

func tcpPortReuse(e *Env) {
	e.StartEngine(e.DefaultConfig())
	target := To(topo.Server4, wire.PortWhoami)
	var spaced app.ReuseResult
	e.RunJSON(Run{App: "alpha", Args: []string{"reuse", "--to", target, "--local-port", "45123", "--gaps", "0,10,100,500,1000", "--count", "6", "--timeout", "3000", "--stall", "100"}, Timeout: 2 * time.Minute}, &spaced)
	e.T.Check(spaced.Stalls == 0, "reusing port 45123 after 0, 10, 100, 500 and 1000 ms never stalls over 100 ms (%d stalls, slowest %.0f ms: %s)", spaced.Stalls, spaced.MaxMS, attempts(spaced.Attempts))
	var burst app.ReuseResult
	e.RunJSON(Run{App: "alpha", Args: []string{"reuse", "--to", target, "--local-port", "45124", "--gaps", "0", "--count", "1000", "--timeout", "3000", "--stall", "100", "--stop-after", "3"}, Timeout: 2 * time.Minute}, &burst)
	e.T.Check(burst.Stalls == 0 && len(burst.Attempts) == 1000, "1,000 immediate reuses of port 45124 without a stall over 100 ms (%d done, %d stalls, slowest %.0f ms)", len(burst.Attempts), burst.Stalls, burst.MaxMS)
}

func attempts(list []app.Attempt) string {
	var parts []string
	for _, a := range list {
		what := topo.LineOfText(a.Seen)
		if a.Err != "" {
			what = engine.LineID(a.Err)
		}
		parts = append(parts, fmt.Sprintf("%s@%.0fms", what, a.TotalMS))
	}
	return strings.Join(parts, " ")
}
