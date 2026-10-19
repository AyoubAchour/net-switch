//go:build linux

package suite

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/app"
	"github.com/AyoubAchour/net-switch/tests/linux/engine"
	"github.com/AyoubAchour/net-switch/tests/linux/harness"
	"github.com/AyoubAchour/net-switch/tests/linux/topo"
	"github.com/AyoubAchour/net-switch/tests/linux/wire"
)

func init() { register(20, addKernel) }

func addKernel(r *registry) {
	r.add("rpfilter.strict", "Strict reverse-path filtering (rp_filter=1): every line still gets its replies", harness.Parity, "5.5", 0, rpFilterStrict)
	r.add("start.old-connections-survive", "Connections opened before start keep their line, including one bound to a line's address", harness.Parity, "5.5", 0,
		func(e *Env) { oldConnections(e, engine.ProfileLinux) })
	r.add("start.old-connections-survive.product-config", "Old connections survive start with today's config as generated (route_exclude_address)", harness.BaselineDefect, "5.5", 0,
		func(e *Env) { oldConnections(e, engine.ProfileProduct) })
	r.add("bypass.lan-and-multicast", "Routers' LANs, link-local and multicast stay on normal routing", harness.Parity, "5.5", 0, lanBypass)
	r.add("bypass.containers", "Container traffic (a docker0 bridge) keeps normal routing", harness.Parity, "5.5", 0,
		func(e *Env) { containers(e, false) })
	r.add("bypass.container-started-later", "A container network created after routing starts keeps normal routing", harness.BaselineDefect, "5.5", 0,
		func(e *Env) { containers(e, true) })
	r.add("routes.default-route-loss-fails-fast", "A line that loses its default route fails its apps' new connections at once", harness.BaselineDefect, "5.5", 0, defaultRouteFailsFast)
	r.add("routes.default-route-loss-and-return", "Losing a line's default route leaves the others alone, and its return needs no restart", harness.Parity, "5.5", 0, defaultRouteReturn)
	r.add("routes.address-change", "A line's address changes mid-flow: other lines' flows stay, new flows use the new address", harness.Parity, "5.5, 5.7", 0, addressChange)
	r.add("flows.address-removed-closes-its-flows", "Flows from a removed address are closed promptly", harness.BaselineDefect, "5.7", 0, addressRemovedCloses)
	r.add("flows.adapter-down-keeps-other-lines", "An adapter going down leaves other lines' flows alone", harness.Parity, "5.7", 0, adapterDownKeepsOthers)
	r.add("flows.adapter-down-closes-its-flows", "An adapter going down closes its own flows promptly", harness.BaselineDefect, "5.7", 0, adapterDownCloses)
	r.add("coexist.foreign-rules-and-marks", "Another tool's rules, marks and tables are kept, including ones on 1.0's own layout", harness.Parity, "3.3, 5.5", 0, foreignRules)
	r.add("cleanup.crash-then-cleanup", "Crash without restart: normal internet in between, then cleanup restores everything", harness.Parity, "2, 3.3, 10", 0, crashCleanup)
	r.add("cleanup.start-stop-cycles", "Five start/stop cycles leave nothing behind", harness.Parity, "10", 0, startStopCycles)
	r.add("netem.loss-and-reordering", "A lossy, reordering, delayed line still carries hashed transfers, connections and UDP", harness.Parity, "10", 3*time.Minute, netemLine)
	r.add("mtu.egress-1280", "A 1280-byte path: TCP both ways over IPv4 and IPv6, and large DNS answers", harness.Parity, "5.8", 3*time.Minute,
		func(e *Env) { smallMTU(e, 1280) })
	r.add("mtu.egress-1400", "A 1400-byte path: TCP both ways over IPv4 and IPv6, and large DNS answers", harness.Parity, "5.8", 3*time.Minute,
		func(e *Env) { smallMTU(e, 1400) })
	r.add("mtu.big-udp-delivered", "Big datagrams an app sent without DF get through a smaller path (fragmented, not dropped)", harness.BaselineDefect, "5.3, 5.8", 0, bigUDP)
	r.add("mtu.df-too-big-reported", "Datagrams that mustn't fragment get 'too big' back (IPv4 DF, IPv6 DONTFRAG)", harness.BaselineDefect, "5.3, 5.8", 0, dfTooBig)
}

func rpFilterStrict(e *Env) {
	if err := e.Net.SetRPFilter(e.Ctx(), 1); err != nil {
		e.T.Fatalf("%v", err)
	}
	e.StartEngine(e.DefaultConfig())
	e.ExpectTCP("alpha with rp_filter=1", "alpha", AsUser, "a", topo.Server4, 5)
	e.ExpectTCP("bravo with rp_filter=1", "bravo", AsUser, "b", topo.Server4, 5)
	e.ExpectTCP("charlie with rp_filter=1", "charlie", AsUser, "c", topo.Server4, 5)
	e.ExpectUDP("bravo UDP with rp_filter=1", "bravo", AsUser, "b", topo.Server4, 10)
	e.ExpectUDP("charlie UDP with rp_filter=1", "charlie", AsUser, "c", topo.Server4, 10)
}

func oldConnections(e *Env, profile engine.Profile) {
	const life = 14 * time.Second
	alpha := e.StartStream("alpha", AsUser, life)
	bravo := e.StartStream("bravo", AsUser, life)
	// An app that chose line b itself, by binding to its interface (as
	// `curl --interface eth-b` does): an outside connection, which stays on
	// that line. (Binding only to the address isn't used: Linux routes such a
	// socket by the main table until source rules exist.)
	bound := e.StartStream("delta", AsUser, life, "--bind-dev", topo.Line("b").Iface)
	e.Sleep(2 * time.Second)
	cfg := e.DefaultConfig()
	cfg.Profile = profile
	e.StartEngine(cfg)
	e.ExpectTCP("a new bravo connection while running", "bravo", AsUser, "b", topo.Server4, 3)
	var sa, sb, sbound Stream
	alpha.WaitJSON(e, 30*time.Second, &sa)
	bravo.WaitJSON(e, 30*time.Second, &sb)
	bound.WaitJSON(e, 30*time.Second, &sbound)
	e.CheckStreamSurvived("alpha's connection from before start", sa, "a")
	e.CheckStreamSurvived("bravo's connection from before start (kernel-routed on a)", sb, "a")
	e.CheckStreamSurvived("delta's connection bound to line b's interface", sbound, "b")
}

func lanBypass(e *Env) {
	e.StartEngine(e.DefaultConfig())
	// Unpinned and unknown traffic through the engine would now leave on c,
	// which can't reach the routers' LANs.
	e.SetLanes(map[engine.LineID]engine.LineID{"a": "c"})
	for _, c := range []struct {
		app    string
		router netip.Addr
		want   string
	}{
		{"alpha", topo.Line("a").GW4, topo.Line("a").Addr4.Addr().String()},
		{"bravo", topo.Line("b").GW4, topo.Line("b").Addr4.Addr().String()},
		{"bravo", topo.Line("a").GW4, topo.Line("a").Addr4.Addr().String()},
	} {
		r := e.TCP(c.app, AsUser, "--to", To(c.router, wire.PortWhoami), "--count", "2", "--timeout", "3000")
		e.T.Check(r.OK == 2 && r.Seen[c.want] == 2, "%s reaches router %s directly from %s (seen %v, errors %v)", c.app, c.router, c.want, r.Seen, r.Errors)
	}
	ll := e.TCP("alpha", AsUser, "--to", "[fe80::1%"+topo.Line("b").Iface+"]:7003", "--count", "2", "--timeout", "3000")
	e.T.Check(ll.OK == 2, "alpha reaches router b's link-local address (seen %v, errors %v)", ll.Seen, ll.Errors)

	// Hold a LAN connection open and send multicast, then look for either
	// among the engine's flows.
	slow := e.Start(Run{App: "alpha", Args: []string{"http", "--url", "http://" + To(topo.Line("a").GW4, wire.PortHTTP) + "/slow?ms=3000"}})
	e.UDP("alpha", AsUser, "--to", "224.0.0.251:5353", "--count", "2", "--wait", "100")
	e.UDP("alpha", AsUser, "--to", "[ff02::fb%"+topo.Line("a").Iface+"]:5353", "--count", "2", "--wait", "100")
	e.Sleep(500 * time.Millisecond)
	var leaked []string
	for _, f := range e.Flows() {
		dst := f.Destination.Addr()
		if dst.IsPrivate() || dst.IsMulticast() || dst.IsLinkLocalUnicast() || netip.MustParsePrefix("192.168.0.0/16").Contains(dst) {
			leaked = append(leaked, f.Protocol+" "+f.Source.String()+" -> "+f.Destination.String())
		}
	}
	e.T.Check(len(leaked) == 0, "no LAN, link-local or multicast traffic among the engine's flows (%s)", strings.Join(leaked, "; "))
	var h app.HTTPResult
	slow.WaitJSON(e, 10*time.Second, &h)
	e.T.Check(h.Status == 200 && h.Seen == topo.Line("a").Addr4.Addr().String(), "alpha's slow LAN request answered directly (seen %q, %s)", h.Seen, h.Err)
}

func containers(e *Env, later bool) {
	if !later {
		if err := e.Net.AddContainer(e.Ctx()); err != nil {
			e.T.Fatalf("container network: %v", err)
		}
	}
	e.StartEngine(e.DefaultConfig())
	if later {
		if err := e.Net.AddContainer(e.Ctx()); err != nil {
			e.T.Fatalf("container network: %v", err)
		}
	}
	// Traffic through the engine would now leave on c; normal routing uses a.
	e.SetLanes(map[engine.LineID]engine.LineID{"a": "c"})
	slow := e.Start(Run{Program: AppPath("delta"), Netns: topo.CTR, User: AsRoot,
		Args: []string{"app", "http", "--url", "http://" + To(topo.Server4, wire.PortHTTP) + "/slow?ms=2500"}})
	var r app.TCPResult
	e.RunJSON(Run{Program: AppPath("delta"), Netns: topo.CTR, User: AsRoot,
		Args: []string{"app", "tcp", "--to", To(topo.Server4, wire.PortWhoami), "--count", "5", "--timeout", "4000"}}, &r)
	lines := Lines(r.Seen)
	e.T.Check(r.OK == 5 && lines["a"] == 5, "the container's connections keep normal routing on line a (lines %s, errors %v)", Describe(lines), r.Errors)
	// Only the container is talking to the HTTP port now. (Its source can't
	// be used: masquerading would rewrite it to the TUN's address on the way
	// into the engine.)
	var seen []string
	for _, f := range e.Flows() {
		if f.Destination.Port() == wire.PortHTTP || f.Source.Addr().String() == topo.ContainerAddr {
			seen = append(seen, f.Protocol+" "+f.Source.String()+" -> "+f.Destination.String())
		}
	}
	e.T.Check(len(seen) == 0, "the engine saw none of the container's traffic (%s)", strings.Join(seen, "; "))
	var h app.HTTPResult
	slow.WaitJSON(e, 10*time.Second, &h)
	e.T.Check(h.Status == 200 && topo.LineOfText(h.Seen) == "a", "the container's slow request answered over line a (seen %q, %s)", h.Seen, h.Err)
}

func defaultRouteFailsFast(e *Env) {
	e.StartEngine(e.DefaultConfig())
	// The lease ended: the default route goes, and the router no longer
	// forwards. Until the control service moves b's lane, b's apps must be
	// refused at once rather than hang.
	if err := e.Net.DelDefault(e.Ctx(), "b"); err != nil {
		e.T.Fatalf("%v", err)
	}
	if err := e.Net.UplinkDown(e.Ctx(), "b"); err != nil {
		e.T.Fatalf("%v", err)
	}
	r := e.TCP("bravo", AsUser, "--to", To(topo.Server4, wire.PortWhoami), "--count", "3", "--timeout", "8000")
	e.T.Check(r.OK == 0 && len(r.Errors) > 0 && r.FailedMS.Max < 1000,
		"bravo's new connections on line b without a default route fail within 1 s (connected %d, errors %v, slowest failure %.0f ms)", r.OK, r.Errors, r.FailedMS.Max)
}

func defaultRouteReturn(e *Env) {
	e.StartEngine(e.DefaultConfig())
	alpha := e.StartStream("alpha", AsUser, 10*time.Second)
	if err := e.Net.DelDefault(e.Ctx(), "b"); err != nil {
		e.T.Fatalf("%v", err)
	}
	e.ExpectTCP("alpha while b has no default route", "alpha", AsUser, "a", topo.Server4, 3)
	e.ExpectTCP("charlie while b has no default route", "charlie", AsUser, "c", topo.Server4, 3)
	if err := e.Net.AddDefault(e.Ctx(), "b"); err != nil {
		e.T.Fatalf("%v", err)
	}
	e.retryLine("bravo once b's default route is back", "bravo", "b", 5*time.Second)
	var s Stream
	alpha.WaitJSON(e, 20*time.Second, &s)
	e.CheckStreamSurvived("alpha's stream throughout", s, "a")
}

// retryLine waits until an app's connections land on a line again, then
// checks a few in a row do.
func (e *Env) retryLine(label, name string, want engine.LineID, within time.Duration) {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		r := e.TCP(name, AsUser, "--to", To(topo.Server4, wire.PortWhoami), "--count", "1", "--timeout", "2000")
		if r.OK == 1 && Lines(r.Seen)[want] == 1 {
			break
		}
		e.Sleep(250 * time.Millisecond)
	}
	e.ExpectTCP(label, name, AsUser, want, topo.Server4, 3)
}

var newAddrB = netip.MustParsePrefix("192.168.2.3/24")

func addressChange(e *Env) {
	e.StartEngine(e.DefaultConfig())
	alpha := e.StartStream("alpha", AsUser, 10*time.Second)
	charlie := e.StartStream("charlie", AsUser, 10*time.Second)
	e.Sleep(time.Second)
	if err := e.Net.ChangeAddress(e.Ctx(), "b", newAddrB); err != nil {
		e.T.Fatalf("%v", err)
	}
	e.retryLine("bravo's new connections after line b's address changed", "bravo", "b", 5*time.Second)
	var sa, sc Stream
	alpha.WaitJSON(e, 20*time.Second, &sa)
	charlie.WaitJSON(e, 20*time.Second, &sc)
	e.CheckStreamSurvived("alpha's stream on a", sa, "a")
	e.CheckStreamSurvived("charlie's stream on c", sc, "c")
}

func addressRemovedCloses(e *Env) {
	e.StartEngine(e.DefaultConfig())
	bravo := e.StartStream("bravo", AsUser, 10*time.Second)
	if _, ok := e.WaitFlow(3*time.Second, func(f engine.Flow) bool { return f.App == AppPath("bravo") && f.Destination.Port() == wire.PortStream }); !ok {
		e.T.Fatalf("the engine never listed bravo's stream")
	}
	changed := time.Now().UnixMilli()
	if err := e.Net.ChangeAddress(e.Ctx(), "b", newAddrB); err != nil {
		e.T.Fatalf("%v", err)
	}
	var s Stream
	bravo.WaitJSON(e, 20*time.Second, &s)
	e.T.Check(s.ClosedAt != 0 && s.ClosedAt-changed <= 3000,
		"bravo's flow from the removed address is closed within 3 s (%s)", closedAfter(s, changed))
}

// closedAfter describes when a stream closed relative to an event (Unix ms).
func closedAfter(s Stream, at int64) string {
	if s.ClosedAt == 0 {
		return fmt.Sprintf("never closed; it went silent for %d ms and the app gave up after %d ms", s.MaxGapMS, s.EndedAt-at)
	}
	return fmt.Sprintf("closed %d ms later with %s", s.ClosedAt-at, s.CloseErr)
}

func adapterDownKeepsOthers(e *Env) {
	e.StartEngine(e.DefaultConfig())
	alpha := e.StartStream("alpha", AsUser, 8*time.Second)
	charlie := e.StartStream("charlie", AsUser, 8*time.Second)
	e.Start(Run{App: "bravo", Args: []string{"stream", "--to", To(topo.Server4, wire.PortStream), "--duration", "8000"}})
	e.Sleep(time.Second)
	if err := e.Net.LinkDown(e.Ctx(), "b"); err != nil {
		e.T.Fatalf("%v", err)
	}
	e.ExpectTCP("alpha with b's adapter down", "alpha", AsUser, "a", topo.Server4, 3)
	var sa, sc Stream
	alpha.WaitJSON(e, 20*time.Second, &sa)
	charlie.WaitJSON(e, 20*time.Second, &sc)
	e.CheckStreamSurvived("alpha's stream on a", sa, "a")
	e.CheckStreamSurvived("charlie's stream on c", sc, "c")
}

func adapterDownCloses(e *Env) {
	e.StartEngine(e.DefaultConfig())
	bravo := e.StartStream("bravo", AsUser, 10*time.Second)
	if _, ok := e.WaitFlow(3*time.Second, func(f engine.Flow) bool { return f.App == AppPath("bravo") && f.Destination.Port() == wire.PortStream }); !ok {
		e.T.Fatalf("the engine never listed bravo's stream")
	}
	down := time.Now().UnixMilli()
	if err := e.Net.LinkDown(e.Ctx(), "b"); err != nil {
		e.T.Fatalf("%v", err)
	}
	var s Stream
	bravo.WaitJSON(e, 20*time.Second, &s)
	e.T.Check(s.ClosedAt != 0 && s.ClosedAt-down <= 3000,
		"bravo's flow on the downed adapter is closed within 3 s (%s)", closedAfter(s, down))
}

// foreignObjects is what other tools on a real PC might have installed: a
// Tailscale-like layout, a default sing-box/mihomo table and rule, a
// WireGuard-style mark, and rules and a mark on 1.0's own base layout (5.5),
// which 1.0 must move around rather than take over. None of them touch the
// suite's traffic unless an engine collides with them.
var foreignObjects = [][]string{
	{"link", "add", "other0", "type", "dummy"},
	{"link", "set", "other0", "up"},
	{"route", "add", "100.64.0.0/10", "dev", "other0", "table", "52"},
	{"-6", "route", "add", "fd7a:115c:a1e0::/48", "dev", "other0", "table", "52"},
	{"rule", "add", "pref", "5210", "fwmark", "0x80000/0xff0000", "lookup", "main"},
	{"rule", "add", "pref", "5250", "fwmark", "0x80000/0xff0000", "unreachable"},
	{"rule", "add", "pref", "5270", "lookup", "52"},
	{"-6", "rule", "add", "pref", "5270", "lookup", "52"},
	{"route", "add", "198.51.100.250/32", "dev", "other0", "table", "2022"},
	{"rule", "add", "pref", "9000", "from", "203.0.113.250", "lookup", "2022"},
	{"route", "add", "198.51.100.251/32", "dev", "other0", "table", "51820"},
	{"rule", "add", "pref", "32764", "not", "fwmark", "0xca6c", "lookup", "51820"},
	// 1.0's base layout: B+9100, B+10000+1 (line 1's mark), B+11000+1, B+12000
	// and table 21000+1. A mark rule that sends line 1's mark into a dead table.
	{"route", "add", "default", "dev", "other0", "table", "21001"},
	{"rule", "add", "pref", "9100", "from", "203.0.113.252", "lookup", "main"},
	{"rule", "add", "pref", "10001", "fwmark", "0x4e530001/0xffffffff", "lookup", "21001"},
	{"rule", "add", "pref", "11001", "from", "203.0.113.251", "lookup", "21001"},
	{"rule", "add", "pref", "12000", "from", "203.0.113.253", "lookup", "main"},
	{"-6", "rule", "add", "pref", "12000", "from", "2001:db8:ffff::1", "lookup", "main"},
}

func foreignRules(e *Env) {
	for _, args := range foreignObjects {
		if _, err := e.Net.R.IP(e.Ctx(), topo.DUT, args...); err != nil {
			e.T.Fatalf("installing another tool's objects: %v", err)
		}
	}
	e.StartEngine(e.DefaultConfig())
	e.ExpectTCP("alpha with other tools' rules", "alpha", AsUser, "a", topo.Server4, 3)
	e.ExpectTCP("bravo with other tools' rules", "bravo", AsUser, "b", topo.Server4, 3)
	e.ExpectTCP("charlie with other tools' rules", "charlie", AsUser, "c", topo.Server4, 3)
	e.ExpectUDP("bravo UDP with other tools' rules", "bravo", AsUser, "b", topo.Server4, 5)
	var removed []string
	for _, d := range e.Snapshot().Diff(e.Before) {
		if strings.Contains(d, ": - ") {
			removed = append(removed, d)
		}
	}
	e.T.Check(len(removed) == 0, "while running, nothing that was there before is gone (%s)", strings.Join(removed, "; "))
	e.StopEngine()
	e.ExpectSameState("after a clean stop", e.Before)

	e.StartEngine(e.DefaultConfig())
	if err := e.Eng.Crash(); err != nil {
		e.T.Fatalf("crash: %v", err)
	}
	e.T.Check(e.Eng.Cleanup(e.Ctx()) == nil, "cleanup after the crash succeeds")
	e.ExpectSameState("after a crash and cleanup", e.Before)
}

func crashCleanup(e *Env) {
	e.StartEngine(e.DefaultConfig())
	e.ExpectTCP("bravo while running", "bravo", AsUser, "b", topo.Server4, 3)
	if err := e.Eng.Crash(); err != nil {
		e.T.Fatalf("crash: %v", err)
	}
	e.T.Check(!e.Eng.Running(), "the engine is gone after the crash")
	// Normal internet works before anyone cleans up.
	e.ExpectTCP("alpha after the crash, before cleanup", "alpha", AsUser, "a", topo.Server4, 3)
	e.ExpectTCP("bravo after the crash, before cleanup (main route)", "bravo", AsUser, "a", topo.Server4, 3)
	e.ExpectUDP("bravo UDP after the crash, before cleanup", "bravo", AsUser, "a", topo.Server4, 5)
	err := e.Eng.Cleanup(e.Ctx())
	e.T.Check(err == nil, "cleanup succeeds (%v)", err)
	e.ExpectSameState("after cleanup", e.Before)
	e.ExpectTCP("alpha after cleanup", "alpha", AsUser, "a", topo.Server4, 3)
	r := e.TCP("alpha", AsUser, "--to", To(topo.Server4, wire.PortWhoami), "--count", "3", "--bind-dev", topo.Line("b").Iface)
	e.T.Check(r.OK == 3 && Lines(r.Seen)["b"] == 3, "an app bound to line b's interface still uses b after cleanup (lines %s, errors %v)", Describe(Lines(r.Seen)), r.Errors)
}

func startStopCycles(e *Env) {
	for i := 1; i <= 5; i++ {
		e.StartEngine(e.DefaultConfig())
		e.ExpectTCP("bravo in cycle "+strconv.Itoa(i), "bravo", AsUser, "b", topo.Server4, 1)
		if !e.StopEngine() {
			return
		}
	}
	e.ExpectSameState("after five start/stop cycles", e.Before)
}

func netemLine(e *Env) {
	if err := e.Net.SetNetem(e.Ctx(), "b", []string{"delay", "10ms", "5ms", "loss", "5%", "reorder", "25%", "50%"}); err != nil {
		e.T.Fatalf("netem: %v", err)
	}
	e.StartEngine(e.DefaultConfig())
	for _, upload := range []bool{false, true} {
		args := []string{"bulk", "--to", To(topo.Server4, wire.PortBulk), "--bytes", "1048576", "--timeout", "90000"}
		if upload {
			args = append(args, "--upload")
		}
		var r app.BulkResult
		e.RunJSON(Run{App: "bravo", Args: args, Timeout: 2 * time.Minute}, &r)
		e.T.Check(r.OK, "bravo 1 MiB %s over the lossy line arrives intact (%d bytes in %.0f ms, %s)", map[bool]string{false: "download", true: "upload"}[upload], r.Bytes, r.MS, r.Err)
	}
	tcp := e.TCP("bravo", AsUser, "--to", To(topo.Server4, wire.PortWhoami), "--count", "20", "--concurrency", "4", "--timeout", "15000")
	e.T.Check(tcp.OK == 20 && Lines(tcp.Seen)["b"] == 20, "bravo's 20 connections over the lossy line all succeed on b (lines %s, errors %v, p95 %.0f ms)", Describe(Lines(tcp.Seen)), tcp.Errors, tcp.Total.P95)
	u := e.UDP("bravo", AsUser, "--to", To(topo.Server4, wire.PortUDPEcho), "--count", "40", "--wait", "2000")
	lines := Lines(u.Seen)
	e.T.Check(u.Received >= 28 && lines["b"] == u.Received, "bravo UDP over the lossy line: %d of %d answered, all on b (lines %s)", u.Received, u.Sent, Describe(lines))
}

func smallMTU(e *Env, mtu int) {
	if err := e.Net.SetUplinkMTU(e.Ctx(), "c", mtu); err != nil {
		e.T.Fatalf("mtu: %v", err)
	}
	cfg := e.DefaultConfig()
	cfg.Policy.IPv6 = true
	e.StartEngine(cfg)
	for _, t := range []struct {
		label  string
		server netip.Addr
		upload bool
		size   string
	}{
		{"IPv4 2 MiB download", topo.Server4, false, "2097152"},
		{"IPv4 1 MiB upload", topo.Server4, true, "1048576"},
		{"IPv6 1 MiB download", topo.Server6, false, "1048576"},
		{"IPv6 1 MiB upload", topo.Server6, true, "1048576"},
	} {
		args := []string{"bulk", "--to", To(t.server, wire.PortBulk), "--bytes", t.size, "--timeout", "60000"}
		if t.upload {
			args = append(args, "--upload")
		}
		var r app.BulkResult
		e.RunJSON(Run{App: "charlie", Args: args, Timeout: 90 * time.Second}, &r)
		e.T.Check(r.OK, "charlie %s over the %d-byte path arrives intact (%d bytes in %.0f ms, %s)", t.label, mtu, r.Bytes, r.MS, r.Err)
	}
	var mid, big app.DNSResult
	e.RunJSON(Run{App: "charlie", Args: []string{"dns", "--server", To(topo.Server4, wire.PortDNS), "--name", "mid.test", "--type", "TXT", "--edns", "4096"}}, &mid)
	e.T.Check(mid.Err == "" && !mid.UDPTruncated && mid.TXTBytes == wire.MidTXTBytes,
		"a %d-byte DNS answer over UDP (fragmented on this path) arrives whole (%d TXT bytes, truncated %v, %s)", mid.Size, mid.TXTBytes, mid.UDPTruncated, mid.Err)
	e.RunJSON(Run{App: "charlie", Args: []string{"dns", "--server", To(topo.Server4, wire.PortDNS), "--name", "big.test", "--type", "TXT", "--edns", "1232"}}, &big)
	e.T.Check(big.Err == "" && big.UDPTruncated && big.TCPFallback && big.TXTBytes == wire.BigTXTBytes,
		"a %d-byte DNS answer is truncated over UDP and arrives over TCP (%d TXT bytes, %s)", big.Size, big.TXTBytes, big.Err)
}

func bigUDP(e *Env) {
	if err := e.Net.SetUplinkMTU(e.Ctx(), "c", 1280); err != nil {
		e.T.Fatalf("mtu: %v", err)
	}
	cfg := e.DefaultConfig()
	cfg.Policy.IPv6 = true
	e.StartEngine(cfg)
	for _, server := range []netip.Addr{topo.Server4, topo.Server6} {
		u := e.UDP("charlie", AsUser, "--to", To(server, wire.PortUDPEcho), "--count", "6", "--size", "1400", "--interval", "200")
		lines := Lines(u.Seen)
		// The first may be lost while the path MTU is learned (IPv6 fragments
		// only at the source); after that, every one must get through.
		e.T.Check(u.Received >= 5 && lines["c"] == u.Received,
			"1400-byte datagrams without DF to %s over a 1280-byte path: %d of %d answered, all on c (lines %s, errors %v)", server, u.Received, u.Sent, Describe(lines), u.SendErrors)
	}
}

func dfTooBig(e *Env) {
	if err := e.Net.SetUplinkMTU(e.Ctx(), "c", 1280); err != nil {
		e.T.Fatalf("mtu: %v", err)
	}
	cfg := e.DefaultConfig()
	cfg.Policy.IPv6 = true
	e.StartEngine(cfg)
	for _, server := range []netip.Addr{topo.Server4, topo.Server6} {
		u := e.UDP("charlie", AsUser, "--to", To(server, wire.PortUDPEcho), "--connect", "--df", "--count", "6", "--size", "1400", "--interval", "300")
		told := u.SendErrors["EMSGSIZE"] + u.RecvErrors["EMSGSIZE"]
		e.T.Check(told > 0, "charlie's 1400-byte don't-fragment datagrams to %s over a 1280-byte path are reported too big (EMSGSIZE %d times; %d of %d answered anyway)", server, told, u.Received, u.Sent)
	}
}
