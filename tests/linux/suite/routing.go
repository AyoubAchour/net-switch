//go:build linux

package suite

import (
	"net/netip"
	"strings"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/app"
	"github.com/AyoubAchour/net-switch/tests/linux/engine"
	"github.com/AyoubAchour/net-switch/tests/linux/harness"
	"github.com/AyoubAchour/net-switch/tests/linux/inet"
	"github.com/AyoubAchour/net-switch/tests/linux/topo"
	"github.com/AyoubAchour/net-switch/tests/linux/wire"
)

func init() { register(10, addRouting) }

func addRouting(r *registry) {
	r.add("lines.three-lines", "Three lines: unpinned apps on the main line, pinned apps on theirs", harness.Parity, "5.4, 5.5", 0, threeLines)
	r.add("lanes.failover-and-failback", "A line loses its internet: its lane moves and comes back, other lines' flows stay", harness.Parity, "4.6, 5.4", 0, failoverFailback)
	r.add("lanes.change-keeps-open-flows", "Pointing a lane elsewhere moves new flows only", harness.Parity, "5.4", 0, laneChangeKeepsFlows)
	r.add("combine.two-to-one", "Combining 2:1 spreads 300 new connections within ±25", harness.Parity, "4.6, 5.4", 0, combineTwoToOne)
	r.add("closeflows.by-line", "closeFlows by line closes that line's flows only", harness.Parity, "4.6, 5.10", 0, closeByLine)
	r.add("closeflows.reconnect", "Reconnect closes an app's flows that aren't on its lane target", harness.Parity, "4.6", 0, closeReconnect)
	r.add("ipv6.not-allowed-rejected-fast", "Public IPv6 is refused at once while IPv6 isn't allowed; link-local IPv6 still works", harness.Parity, "5.4", 0, ipv6Rejected)
	r.add("ipv6.routed-per-line", "With IPv6 allowed, IPv6 TCP and UDP take each app's line", harness.Parity, "5.4, 5.5", 0, ipv6PerLine)
	r.add("ipv6.disabled-default-with-capable-line", "A disabled IPv6 default cannot bypass pins, blocked lines or IPv6 refusal", harness.Requires10, "5.4, 5.5", 0, ipv6DisabledDefault)
	r.defect("flows.ipv6-off-closes-only-ipv6", "Turning IPv6 off closes the IPv6 flows and only them",
		"today's app restarts the engine to change IPv6, which closes every flow", "5.7", 0, ipv6Off)
	r.add("icmp.echo-follows-main-lane", "Ping (IPv4 and IPv6) reaches the server over the main line's lane target, with real replies", harness.Parity, "5.4, 5.8", 0, icmpEcho)
	r.add("dns.queries-per-line", "DNS over UDP and TCP leaves on each app's line", harness.Parity, "5.4", 0, dnsPerLine)
}

func ipv6DisabledDefault(e *Env) {
	out, err := e.Net.R.In(e.Ctx(), topo.DUT, "sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1")
	e.T.Require(err == nil, "disable IPv6 only for subsequently created interfaces (%s, %v)", out, err)
	e.T.Require(e.SysctlDUT("net.ipv6.conf."+topo.Line("b").Iface+".disable_ipv6") == "0", "line b retains IPv6 despite the disabled default")
	cfg := e.DefaultConfig()
	cfg.Policy.IPv6 = true
	e.StartEngine(cfg)
	e.ExpectTCP("pinned IPv6 with disabled default", "bravo", AsUser, "b", topo.Server6, 3)
	e.ExpectUDP("pinned IPv6 UDP with disabled default", "bravo", AsUser, "b", topo.Server6, 3)
	for _, blocked := range []bool{true, false} {
		p := cfg.Policy
		label := "blocked/capped line"
		if blocked {
			p.Blocked = []engine.LineID{"b"}
		} else {
			p.IPv6 = false
			label = "IPv6 not allowed"
		}
		e.Apply(p)
		from := e.Mark()
		tcp := e.TCP("bravo", AsUser, "--to", To(topo.Server6, wire.PortWhoami), "--count", "3", "--timeout", "3000")
		var udp app.UDPResult
		e.RunJSON(Run{App: "bravo", Args: []string{"udp", "--to", To(topo.Server6, wire.PortUDPEcho), "--count", "3", "--wait", "1000", "--connect"}}, &udp)
		refused := udp.RecvErrors["ECONNREFUSED"] + udp.SendErrors["ECONNREFUSED"]
		e.T.Check(tcp.OK == 0 && tcp.FailedMS.Max < 1000 && tcp.Errors["ECONNREFUSED"]+tcp.Errors["ECONNRESET"] == 3 && udp.Received == 0 && refused == 3,
			"%s promptly refuses every IPv6 TCP and UDP attempt (%d/%d replies, %d UDP refusals)", label, tcp.OK, udp.Received, refused)
		escaped := Select(e.Records(), func(r inet.Record) bool {
			return r.T >= from && (r.Kind == "tcp" || r.Kind == "udp") && strings.HasPrefix(r.Dst, "[")
		})
		e.T.Check(len(escaped) == 0, "%s sends no public IPv6 to a server (%d escaped)", label, len(escaped))
	}
	e.T.Check(e.SysctlDUT("net.ipv6.conf.default.disable_ipv6") == "1", "enabling our TUN did not change the system default")
}

func threeLines(e *Env) {
	e.StartEngine(e.DefaultConfig())
	e.ExpectTCP("alpha, unpinned", "alpha", AsUser, "a", topo.Server4, 5)
	e.ExpectTCP("bravo, pinned to b", "bravo", AsUser, "b", topo.Server4, 5)
	e.ExpectTCP("charlie, pinned to c", "charlie", AsUser, "c", topo.Server4, 5)
	e.ExpectTCP("bravo run as root", "bravo", AsRoot, "b", topo.Server4, 3)
	e.ExpectUDP("alpha UDP", "alpha", AsUser, "a", topo.Server4, 10)
	e.ExpectUDP("bravo UDP", "bravo", AsUser, "b", topo.Server4, 10)
	e.ExpectUDP("charlie UDP", "charlie", AsUser, "c", topo.Server4, 10)
	var h app.HTTPResult
	e.RunJSON(Run{App: "bravo", Args: []string{"http", "--url", "http://" + To(topo.Server4, wire.PortHTTP) + "/"}}, &h)
	e.T.Check(h.Status == 200 && topo.LineOfText(h.Seen) == "b", "bravo HTTP: status %d, server saw %q (line %q) %s", h.Status, h.Seen, topo.LineOfText(h.Seen), h.Err)

	// The engine's own view of a flow: its app, lane and physical line.
	s := e.StartStream("bravo", AsUser, 4*time.Second)
	f, ok := e.WaitFlow(3*time.Second, func(f engine.Flow) bool {
		return f.App == AppPath("bravo") && f.Destination.Port() == wire.PortStream
	})
	if e.T.Check(ok, "the engine lists bravo's stream as a flow") {
		e.T.Check(f.Protocol == "tcp" && f.Line == "b" && f.Lane == "b", "bravo's flow: protocol %s, lane %s, line %s (want tcp, b, b)", f.Protocol, f.Lane, f.Line)
	}
	var st Stream
	s.WaitJSON(e, 10*time.Second, &st)
	e.CheckStreamSurvived("bravo's stream", st, "b")
}

func failoverFailback(e *Env) {
	e.StartEngine(e.DefaultConfig())
	alpha := e.StartStream("alpha", AsUser, 12*time.Second)
	charlie := e.StartStream("charlie", AsUser, 12*time.Second)
	e.Sleep(time.Second)
	e.ExpectTCP("bravo before", "bravo", AsUser, "b", topo.Server4, 3)

	// Line b stays up on the PC but its router loses the internet. The
	// control service notices and points b's lane at the main line.
	if err := e.Net.UplinkDown(e.Ctx(), "b"); err != nil {
		e.T.Fatalf("%v", err)
	}
	e.SetLanes(map[engine.LineID]engine.LineID{"b": "a"})
	e.ExpectTCP("bravo while b is down (lane b -> a)", "bravo", AsUser, "a", topo.Server4, 5)
	e.ExpectUDP("bravo UDP while b is down", "bravo", AsUser, "a", topo.Server4, 5)

	if err := e.Net.UplinkUp(e.Ctx(), "b"); err != nil {
		e.T.Fatalf("%v", err)
	}
	e.SetLanes(map[engine.LineID]engine.LineID{"b": "b"})
	e.ExpectTCP("bravo after failback", "bravo", AsUser, "b", topo.Server4, 5)

	var sa, sc Stream
	alpha.WaitJSON(e, 20*time.Second, &sa)
	charlie.WaitJSON(e, 20*time.Second, &sc)
	e.CheckStreamSurvived("alpha's stream on a", sa, "a")
	e.CheckStreamSurvived("charlie's stream on c", sc, "c")
}

func laneChangeKeepsFlows(e *Env) {
	e.StartEngine(e.DefaultConfig())
	bravo := e.StartStream("bravo", AsUser, 8*time.Second)
	e.Sleep(time.Second)
	e.SetLanes(map[engine.LineID]engine.LineID{"b": "c"})
	e.ExpectTCP("bravo's new connections after lane b -> c", "bravo", AsUser, "c", topo.Server4, 5)
	var s Stream
	bravo.WaitJSON(e, 15*time.Second, &s)
	e.CheckStreamSurvived("bravo's stream opened before the change", s, "b")
}

func combineTwoToOne(e *Env) {
	cfg := e.DefaultConfig()
	cfg.Policy.Combine = true
	cfg.Policy.Shares = map[engine.LineID]float64{"a": 2.0 / 3, "b": 1.0 / 3}
	e.StartEngine(cfg)
	var dests []string
	for _, addr := range topo.ManyServers()[:10] {
		dests = append(dests, To(addr, wire.PortWhoami))
	}
	for _, run := range []struct {
		label       string
		concurrency string
	}{{"one at a time", "1"}, {"16 at once", "16"}} {
		r := e.TCP("alpha", AsUser, "--to", strings.Join(dests, ","), "--count", "300", "--concurrency", run.concurrency, "--timeout", "5000")
		lines := Lines(r.Seen)
		e.T.Check(r.OK == 300 && lines["c"] == 0 && lines["?"] == 0 && within(lines["a"], 200, 25) && within(lines["b"], 100, 25),
			"alpha, 300 connections %s over 10 servers: lines %s (want a 200±25, b 100±25, c 0; errors %v)", run.label, Describe(lines), r.Errors)
	}
	e.ExpectTCP("bravo stays on its pinned line while combining", "bravo", AsUser, "b", topo.Server4, 10)
}

func within(got, want, slack int) bool { return got >= want-slack && got <= want+slack }

func closeByLine(e *Env) {
	e.StartEngine(e.DefaultConfig())
	bravo := e.StartStream("bravo", AsUser, 8*time.Second)
	charlie := e.StartStream("charlie", AsUser, 8*time.Second)
	for _, name := range []string{"bravo", "charlie"} {
		if _, ok := e.WaitFlow(3*time.Second, func(f engine.Flow) bool { return f.App == AppPath(name) && f.Destination.Port() == wire.PortStream }); !ok {
			e.T.Fatalf("the engine never listed %s's stream", name)
		}
	}
	asked := time.Now().UnixMilli()
	res, err := e.Eng.CloseFlows(e.Ctx(), engine.Selector{Line: "b"})
	if err != nil {
		e.T.Fatalf("closeFlows: %v", err)
	}
	e.T.Check(res.Closed >= 1 && res.Failed == 0, "closeFlows{line b}: %+v", res)
	var sb, sc Stream
	bravo.WaitJSON(e, 15*time.Second, &sb)
	charlie.WaitJSON(e, 15*time.Second, &sc)
	e.T.Check(sb.ClosedAt != 0 && sb.ClosedAt-asked <= 2000, "bravo's stream on b closed within 2 s (closed %d ms after the request, %q)", sb.ClosedAt-asked, sb.CloseErr)
	e.CheckStreamSurvived("charlie's stream on c", sc, "c")
}

func closeReconnect(e *Env) {
	e.StartEngine(e.DefaultConfig())
	bravo := e.StartStream("bravo", AsUser, 8*time.Second)
	alpha := e.StartStream("alpha", AsUser, 8*time.Second)
	if _, ok := e.WaitFlow(3*time.Second, func(f engine.Flow) bool { return f.App == AppPath("bravo") && f.Destination.Port() == wire.PortStream }); !ok {
		e.T.Fatalf("the engine never listed bravo's stream")
	}
	// Reconnect for a pinned app whose lane now points at c: close its flows
	// that aren't on c (4.6).
	e.SetLanes(map[engine.LineID]engine.LineID{"b": "c"})
	asked := time.Now().UnixMilli()
	res, err := e.Eng.CloseFlows(e.Ctx(), engine.Selector{App: AppPath("bravo"), NotLine: "c"})
	if err != nil {
		e.T.Fatalf("closeFlows: %v", err)
	}
	e.T.Check(res.Closed >= 1, "closeFlows{bravo, not c}: %+v", res)
	e.ExpectTCP("bravo reconnects on c", "bravo", AsUser, "c", topo.Server4, 3)
	var sb, sa Stream
	bravo.WaitJSON(e, 15*time.Second, &sb)
	alpha.WaitJSON(e, 15*time.Second, &sa)
	e.T.Check(sb.ClosedAt != 0 && sb.ClosedAt-asked <= 2000, "bravo's old stream closed within 2 s (%d ms, %q)", sb.ClosedAt-asked, sb.CloseErr)
	e.CheckStreamSurvived("alpha's stream", sa, "a")
}

func ipv6Rejected(e *Env) {
	e.StartEngine(e.DefaultConfig())
	r := e.TCP("alpha", AsUser, "--to", To(topo.Server6, wire.PortWhoami), "--count", "5", "--timeout", "5000")
	e.T.Check(r.OK == 0 && r.FailedMS.Max < 1000,
		"alpha's public IPv6 connections are refused at once: %d of 5 connected, errors %v, slowest failure %.0f ms", r.OK, r.Errors, r.FailedMS.Max)
	// Link-local IPv6 isn't public: it bypasses the engine and works.
	ll := e.TCP("alpha", AsUser, "--to", "[fe80::1%"+topo.Line("a").Iface+"]:7003", "--count", "2", "--timeout", "3000")
	e.T.Check(ll.OK == 2, "alpha reaches router a's link-local address: %d of 2 (errors %v, seen %v)", ll.OK, ll.Errors, ll.Seen)
}

func ipv6PerLine(e *Env) {
	cfg := e.DefaultConfig()
	cfg.Policy.IPv6 = true
	e.StartEngine(cfg)
	e.ExpectTCP("alpha IPv6", "alpha", AsUser, "a", topo.Server6, 5)
	e.ExpectTCP("bravo IPv6", "bravo", AsUser, "b", topo.Server6, 5)
	e.ExpectTCP("charlie IPv6", "charlie", AsUser, "c", topo.Server6, 5)
	e.ExpectUDP("bravo IPv6 UDP", "bravo", AsUser, "b", topo.Server6, 10)
	e.ExpectUDP("charlie IPv6 UDP", "charlie", AsUser, "c", topo.Server6, 10)
	e.ExpectTCP("alpha IPv4 still works", "alpha", AsUser, "a", topo.Server4, 3)
}

func ipv6Off(e *Env) {
	cfg := e.DefaultConfig()
	cfg.Policy.IPv6 = true
	e.StartEngine(cfg)
	v4 := e.StartStream("bravo", AsUser, 10*time.Second)
	v6 := e.Start(Run{App: "bravo", Args: []string{"stream", "--to", To(topo.Server6, wire.PortStream), "--duration", "10000", "--interval", "100"}})
	for _, server := range []netip.Addr{topo.Server4, topo.Server6} {
		_, ok := e.WaitFlow(3*time.Second, func(f engine.Flow) bool {
			return f.App == AppPath("bravo") && f.Destination.Addr() == server && f.Destination.Port() == wire.PortStream
		})
		e.T.Require(ok, "the engine lists bravo's stream to %s before IPv6 is turned off", server)
	}
	p := cfg.Policy
	p.IPv6 = false
	off := time.Now().UnixMilli()
	e.Apply(p)
	var s4, s6 Stream
	v4.WaitJSON(e, 20*time.Second, &s4)
	v6.WaitJSON(e, 20*time.Second, &s6)
	e.T.Check(s4.Connected && s6.Connected, "both streams were up before (IPv4 %v, IPv6 %v)", s4.Connected, s6.Connected)
	// Mandatory: IPv6 traffic stops when IPv6 is turned off, and the IPv4
	// stream's answers only ever came over b. The defect is collateral: the
	// IPv4 stream closing too.
	lines4 := StreamLines(s4)
	e.T.Check(s6.ClosedAt != 0 && s6.ClosedAt-off <= 2000, "turning IPv6 off closes bravo's IPv6 stream within 2 s (%s)", closedAfter(s6, off))
	e.T.Check(lines4["b"] == s4.Pongs, "every answer bravo's IPv4 stream got came over b (%s)", Describe(lines4))
	e.T.Expect(s4.ClosedAt == 0 && s4.MaxGapMS < 2000 && s4.Pongs > 0,
		"turning IPv6 off leaves bravo's IPv4 stream running (%s, pongs %d, longest silence %d ms)", closedAfter(s4, off), s4.Pongs, s4.MaxGapMS)
	r := e.TCP("bravo", AsUser, "--to", To(topo.Server6, wire.PortWhoami), "--count", "3", "--timeout", "5000")
	e.T.Check(r.OK == 0 && r.FailedMS.Max < 1000, "new IPv6 connections are refused at once now (connected %d, slowest failure %.0f ms)", r.OK, r.FailedMS.Max)
	e.ExpectTCP("bravo's IPv4 still uses b", "bravo", AsUser, "b", topo.Server4, 3)
}

// pingVia pings dst and checks the replies, and that the server saw every
// request arrive from line want.
func (e *Env) pingVia(label string, dst netip.Addr, want engine.LineID) {
	var r app.PingResult
	e.RunJSON(Run{App: "alpha", Args: []string{"ping", "--to", dst.String(), "--count", "3", "--interval", "100"}}, &r)
	recs, _ := e.WaitRecords(3*time.Second, func(recs []inet.Record) bool {
		return len(Select(recs, Tagged("icmp", r.Token))) >= r.Sent
	})
	got := RecordLines(Select(recs, Tagged("icmp", r.Token)))
	e.T.Check(r.Received == 3 && got[want] == 3 && len(got) == 1,
		"%s: %d of 3 replies, the server saw the requests from lines %s (want 3 from %s; errors %v)", label, r.Received, Describe(got), want, r.Errors)
}

func icmpEcho(e *Env) {
	cfg := e.DefaultConfig()
	cfg.Policy.IPv6 = true
	e.StartEngine(cfg)
	e.pingVia("ping IPv4", topo.Server4, "a")
	e.pingVia("ping IPv6", topo.Server6, "a")
	// Echo has no owner, so it follows the main line's lane target.
	e.SetLanes(map[engine.LineID]engine.LineID{"a": "c"})
	e.pingVia("ping IPv4 with the main lane on c", topo.Server4, "c")
	e.pingVia("ping IPv6 with the main lane on c", topo.Server6, "c")
}

func dnsPerLine(e *Env) {
	e.StartEngine(e.DefaultConfig())
	server := To(topo.Server4, wire.PortDNS)
	for _, run := range []struct {
		name string
		want engine.LineID
		tcp  bool
	}{{"alpha", "a", false}, {"bravo", "b", false}, {"charlie", "c", false}, {"bravo", "b", true}} {
		args := []string{"dns", "--server", server, "--name", "whoami.test", "--type", "A"}
		if run.tcp {
			args = append(args, "--tcp")
		}
		var r app.DNSResult
		e.RunJSON(Run{App: run.name, Args: args}, &r)
		seen := ""
		if len(r.Addresses) > 0 {
			seen = r.Addresses[0]
		}
		e.T.Check(r.Err == "" && topo.LineOfText(seen) == run.want,
			"%s DNS (tcp %v): answered %q (line %q, want %s) %s", run.name, run.tcp, seen, topo.LineOfText(seen), run.want, r.Err)
	}
}
