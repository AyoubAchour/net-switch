//go:build linux

package suite

import (
	"fmt"
	"net/netip"
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

func init() { register(20, addKernel) }

func addKernel(r *registry) {
	r.add("rpfilter.strict", "Strict reverse-path filtering (rp_filter=1) stays on, and every line still gets its replies", harness.Parity, "5.5", 0, rpFilterStrict)
	r.add("start.old-connections-survive", "Connections opened before start keep their line, including one bound to a line's interface", harness.Parity, "5.5", 0,
		func(e *Env) { oldConnections(e, engine.ProfileLinux) })
	r.defect("start.old-connections-survive.product-config", "Old connections survive start with today's config as generated",
		"today's config keeps route_exclude_address, whose routes reset connections opened before start", "5.5", 0,
		func(e *Env) { oldConnections(e, engine.ProfileProduct) })
	r.add("start.new-address-bound-sockets", "A new socket an app binds to a line's address while routing runs leaves on that line, outside the engine", harness.Parity, "5.5", 0, newAddressBound)
	r.add("bypass.lan-and-multicast", "Routers' LANs, link-local and multicast stay on normal routing", harness.Parity, "5.5", 0, lanBypass)
	r.add("bypass.containers", "Container traffic (a docker0 bridge) keeps normal routing", harness.Parity, "5.5", 0,
		func(e *Env) { containers(e, false) })
	r.defect("bypass.container-started-later", "A container network created after routing starts keeps normal routing",
		"exclude_interface is fixed at start, so a bridge created later sends its traffic through the engine", "5.5", 0,
		func(e *Env) { containers(e, true) })
	r.defect("routes.default-route-removed", "A line that loses its default route refuses its apps at once, sends nothing, and recovers when the route returns",
		"sing-box binds the line's interface and, with no route, treats the destination as on-link: the app waits about 3 s on ARP before it's refused", "5.5", 0, defaultRouteRemoved)
	r.add("routes.uplink-down", "A line whose router loses the internet: its apps' connections fail without ever looking connected, other lines carry on, and it recovers without a restart", harness.Parity, "5.2, 5.5", 0, uplinkDown)
	r.add("routes.address-change", "A line's address changes mid-flow: other lines' flows stay, new flows use the new address", harness.Parity, "5.5, 5.7", 0, addressChange)
	r.defect("flows.address-removed-closes-its-flows", "Flows from a removed address are closed promptly",
		"flows whose source address is removed are never closed; they hang until the app gives up", "5.7", 0, addressRemovedCloses)
	r.add("flows.adapter-down-keeps-other-lines", "An adapter going down leaves other lines' flows alone", harness.Parity, "5.7", 0, adapterDownKeepsOthers)
	r.defect("flows.adapter-down-closes-its-flows", "An adapter going down closes its own flows promptly",
		"flows on an adapter that goes down are never closed; they hang until the app gives up", "5.7", 0, adapterDownCloses)
	r.add("flows.dns-change-keeps-flows", "Changing the PC's DNS servers closes no flow", harness.Parity, "5.7", 0, dnsChange)
	r.add("coexist.foreign-rules-and-marks", "Another tool's rules, marks and tables are kept, including ones on 1.0's own layout", harness.Parity, "3.3, 5.5", 0, foreignRules)
	r.add("cleanup.crash-then-cleanup", "Crash without restart: normal internet in between, then cleanup restores everything", harness.Parity, "2, 3.3, 10", 0, crashCleanup)
	r.add("cleanup.start-stop-cycles", "Five start/stop cycles leave nothing behind", harness.Parity, "10", 0, startStopCycles)
	r.add("netem.loss-and-reordering", "A lossy, reordering, delayed line still carries hashed transfers, connections and UDP", harness.Parity, "10", 3*time.Minute, netemLine)
	r.add("mtu.egress-1280", "A 1280-byte path: TCP both ways over IPv4 and IPv6 and large DNS answers, all over that line", harness.Parity, "5.8", 3*time.Minute,
		func(e *Env) { smallMTU(e, 1280) })
	r.add("mtu.egress-1400", "A 1400-byte path: TCP both ways over IPv4 and IPv6 and large DNS answers, all over that line", harness.Parity, "5.8", 3*time.Minute,
		func(e *Env) { smallMTU(e, 1400) })
	r.defect("mtu.big-udp-delivered", "Big datagrams an app sent without DF get through a smaller path (fragmented, not dropped)",
		"sing-box sets DF on its own UDP sockets (udp_fragment is off by default), so an app's oversized datagram is silently dropped", "5.3, 5.8", 0, bigUDP)
	r.defect("mtu.df-too-big-reported", "Datagrams that mustn't fragment get 'too big' back, and none of them gets out",
		"no ICMP frag-needed or Packet Too Big ever reaches the app", "5.3, 5.8", 0, dfTooBig)
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
	// The kernel uses the stricter of "all" and the interface's own value, so
	// every one must still read 1 while the engine runs.
	keys := []string{"net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter"}
	for _, l := range topo.Lines {
		keys = append(keys, "net.ipv4.conf."+l.Iface+".rp_filter")
	}
	var loosened []string
	for _, key := range keys {
		if v := e.SysctlDUT(key); v != "1" {
			loosened = append(loosened, key+"="+v)
		}
	}
	e.T.Check(len(loosened) == 0, "strict reverse-path filtering is still on everywhere while the engine runs (changed: %s)", strings.Join(loosened, ", "))
}

func oldConnections(e *Env, profile engine.Profile) {
	const life = 14 * time.Second
	alpha := e.StartStream("alpha", AsUser, life)
	bravo := e.StartStream("bravo", AsUser, life)
	// An app that chose line b itself, by binding to its interface (as
	// `curl --interface eth-b` does): an outside connection, which stays on
	// that line. A socket bound only to the address before start is 5.5's
	// accepted edge case and isn't checked.
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
	e.T.Check(sa.Connected && sb.Connected && sbound.Connected, "all three connections were up before start")
	survived := func(s Stream, want engine.LineID) bool {
		lines := StreamLines(s)
		return s.ClosedAt == 0 && s.MaxGapMS < 2000 && s.Pongs > 0 && lines[want] == s.Pongs
	}
	describe := func(s Stream) string {
		return fmt.Sprintf("lines %s, longest silence %d ms, closed %q", Describe(StreamLines(s)), s.MaxGapMS, s.CloseErr)
	}
	ok := survived(sa, "a") && survived(sb, "a") && survived(sbound, "b")
	text := "connections from before start keep running on their lines: alpha on a (%s), bravo on a (%s), delta bound to b's interface on b (%s)"
	if profile == engine.ProfileProduct {
		e.T.Expect(ok, text, describe(sa), describe(sb), describe(sbound))
	} else {
		e.T.Check(ok, text, describe(sa), describe(sb), describe(sbound))
	}
}

func newAddressBound(e *Env) {
	e.StartEngine(e.DefaultConfig())
	for _, id := range []engine.LineID{"b", "c"} {
		addr := topo.Line(id).Addr4.Addr().String()
		r := e.TCP("alpha", AsUser, "--to", To(topo.Server4, wire.PortWhoami), "--count", "3", "--local-addr", addr)
		lines := Lines(r.Seen)
		e.T.Check(r.OK == 3 && lines[id] == 3, "alpha's new sockets bound to %s leave on line %s (lines %s, errors %v)", addr, id, Describe(lines), r.Errors)
	}
	s := e.Start(Run{App: "alpha", Args: []string{"stream", "--to", To(topo.Server4, wire.PortStream), "--duration", "3000", "--interval", "100", "--local-addr", topo.Line("b").Addr4.Addr().String()}})
	e.Sleep(time.Second)
	var seen []string
	for _, f := range FlowsOf(e.Flows(), AppPath("alpha")) {
		seen = append(seen, f.Protocol+" "+f.Source.String()+" -> "+f.Destination.String())
	}
	e.T.Check(len(seen) == 0, "the engine carries none of alpha's address-bound connections (it lists %s)", strings.Join(seen, "; "))
	var st Stream
	s.WaitJSON(e, 10*time.Second, &st)
	e.CheckStreamSurvived("alpha's address-bound stream", st, "b")
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
	// Only the container is talking to the HTTP port now. (Its source can't
	// be used: masquerading would rewrite it to the TUN's address on the way
	// into the engine.)
	var seen []string
	for _, f := range e.Flows() {
		if f.Destination.Port() == wire.PortHTTP || f.Source.Addr().String() == topo.ContainerAddr {
			seen = append(seen, f.Protocol+" "+f.Source.String()+" -> "+f.Destination.String())
		}
	}
	var h app.HTTPResult
	slow.WaitJSON(e, 10*time.Second, &h)
	lines := Lines(r.Seen)
	e.T.Check(r.OK == 5 && h.Status == 200, "the container's requests all completed (%d of 5 connections, HTTP %d %s)", r.OK, h.Status, h.Err)
	ok := lines["a"] == 5 && topo.LineOfText(h.Seen) == "a" && len(seen) == 0
	text := "the container keeps normal routing on line a and the engine sees none of it (connections on %s, slow request on %q, engine flows: %s)"
	if later {
		e.T.Expect(ok, text, Describe(lines), topo.LineOfText(h.Seen), strings.Join(seen, "; "))
	} else {
		e.T.Check(ok, text, Describe(lines), topo.LineOfText(h.Seen), strings.Join(seen, "; "))
	}
}

func defaultRouteRemoved(e *Env) {
	e.StartEngine(e.DefaultConfig())
	e.ExpectTCP("bravo before", "bravo", AsUser, "b", topo.Server4, 3)
	if err := e.Net.DelDefault(e.Ctx(), "b"); err != nil {
		e.T.Fatalf("%v", err)
	}
	// Wait until no table on the PC still has a default route through b: the
	// control side (1.0's reconciler, the driver's emulation on the baseline)
	// has seen the change.
	iface := topo.Line("b").Iface
	deadline := time.Now().Add(5 * time.Second)
	left := ""
	for {
		left = ""
		for _, family := range []string{"-4", "-6"} {
			out, err := e.Net.R.IP(e.Ctx(), topo.DUT, family, "route", "show", "table", "all", "default", "dev", iface)
			if err != nil {
				e.T.Fatalf("%v", err)
			}
			left += strings.TrimSpace(out)
		}
		if left == "" || time.Now().After(deadline) {
			break
		}
		e.Sleep(100 * time.Millisecond)
	}
	e.T.Require(left == "", "within 5 s no routing table has a default route through b any more (%s)", left)
	from := time.Now().UnixMilli()
	r := e.TCP("bravo", AsUser, "--to", To(topo.Server4, wire.PortWhoami), "--count", "3", "--timeout", "8000")
	to := time.Now().UnixMilli()
	leaked := Select(e.Records(), func(rec inet.Record) bool { return rec.Kind == "tcp" && rec.T >= from && rec.T <= to })
	e.ExpectTCP("alpha while b has no default route", "alpha", AsUser, "a", topo.Server4, 3)
	e.ExpectTCP("charlie while b has no default route", "charlie", AsUser, "c", topo.Server4, 3)
	e.T.Expect(r.OK == 0 && r.FailedMS.Max < 1000 && len(leaked) == 0,
		"with no default route on b, bravo's new connections are refused within 1 s and none reaches the internet (connected %d, slowest failure %.0f ms, errors %v, arrived at servers %d)",
		r.OK, r.FailedMS.Max, r.Errors, len(leaked))
	if err := e.Net.AddDefault(e.Ctx(), "b"); err != nil {
		e.T.Fatalf("%v", err)
	}
	e.retryLine("bravo once b's default route is back, without a restart", "bravo", "b", 5*time.Second)
}

func uplinkDown(e *Env) {
	e.StartEngine(e.DefaultConfig())
	alpha := e.StartStream("alpha", AsUser, 20*time.Second)
	if err := e.Net.UplinkDown(e.Ctx(), "b"); err != nil {
		e.T.Fatalf("%v", err)
	}
	r := e.TCP("bravo", AsUser, "--to", To(topo.Server4, wire.PortWhoami), "--count", "2", "--concurrency", "2", "--timeout", "15000")
	connected := 0
	for _, a := range r.Attempts {
		if a.Connected {
			connected++
		}
	}
	e.T.Check(r.OK == 0 && connected == 0 && r.FailedMS.Max <= 12000,
		"bravo's connections over a line that reaches nothing fail without the handshake ever completing, within the 10 s dial deadline (completed handshakes %d, slowest failure %.0f ms, errors %v)",
		connected, r.FailedMS.Max, r.Errors)
	e.ExpectTCP("charlie while b's router is cut off", "charlie", AsUser, "c", topo.Server4, 3)
	if err := e.Net.UplinkUp(e.Ctx(), "b"); err != nil {
		e.T.Fatalf("%v", err)
	}
	e.retryLine("bravo once b's router is back, without a restart", "bravo", "b", 5*time.Second)
	var s Stream
	alpha.WaitJSON(e, 40*time.Second, &s)
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

// streamUp waits until the engine lists an app's stream and the stream is
// still running, so a case acts on a flow that really exists. (Its answers
// are checked from its result afterwards.)
func (e *Env) streamUp(name string, bg *Bg) {
	_, ok := e.WaitFlow(3*time.Second, func(f engine.Flow) bool {
		return f.App == AppPath(name) && f.Destination.Port() == wire.PortStream && f.Down > 0
	})
	e.T.Require(ok, "the engine lists %s's stream, with answers flowing", name)
	e.T.Require(bg.Running(), "%s's stream is still running", name)
}

func addressRemovedCloses(e *Env) {
	e.StartEngine(e.DefaultConfig())
	bravo := e.StartStream("bravo", AsUser, 10*time.Second)
	e.streamUp("bravo", bravo)
	changed := time.Now().UnixMilli()
	if err := e.Net.ChangeAddress(e.Ctx(), "b", newAddrB); err != nil {
		e.T.Fatalf("%v", err)
	}
	var s Stream
	bravo.WaitJSON(e, 20*time.Second, &s)
	e.T.Check(s.Connected && s.Pongs > 0 && StreamLines(s)["b"] == s.Pongs, "bravo's stream was up on b before the change (%d pongs, lines %s)", s.Pongs, Describe(StreamLines(s)))
	e.T.Expect(s.ClosedAt != 0 && s.ClosedAt-changed <= 3000,
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
	e.streamUp("bravo", bravo)
	down := time.Now().UnixMilli()
	if err := e.Net.LinkDown(e.Ctx(), "b"); err != nil {
		e.T.Fatalf("%v", err)
	}
	var s Stream
	bravo.WaitJSON(e, 20*time.Second, &s)
	e.T.Check(s.Connected && s.Pongs > 0 && StreamLines(s)["b"] == s.Pongs, "bravo's stream was up on b before the adapter went down (%d pongs, lines %s)", s.Pongs, Describe(StreamLines(s)))
	e.T.Expect(s.ClosedAt != 0 && s.ClosedAt-down <= 3000,
		"bravo's flow on the downed adapter is closed within 3 s (%s)", closedAfter(s, down))
}

// dnsChange changes the resolver configuration the engine sees mid-flow.
// The engine runs under `ip netns exec`, which mounts /etc/netns/<ns>/ files
// over /etc; rewriting the file in place is a DNS change it can notice.
func dnsChange(e *Env) {
	dir := "/etc/netns/" + topo.DUT
	if err := os.MkdirAll(dir, 0o755); err != nil {
		e.T.Fatalf("%v", err)
	}
	e.T.Cleanup(func() { _ = os.RemoveAll(dir) })
	conf := dir + "/resolv.conf"
	if err := os.WriteFile(conf, []byte("nameserver "+topo.Server4.String()+"\n"), 0o644); err != nil {
		e.T.Fatalf("%v", err)
	}
	e.StartEngine(e.DefaultConfig())
	streams := map[string]*Bg{}
	for _, name := range []string{"alpha", "bravo", "charlie"} {
		streams[name] = e.StartStream(name, AsUser, 10*time.Second)
	}
	e.Sleep(2 * time.Second)
	if err := os.WriteFile(conf, []byte("nameserver "+topo.Server4b.String()+"\nnameserver "+topo.Server6.String()+"\n"), 0o644); err != nil {
		e.T.Fatalf("%v", err)
	}
	e.Sleep(2 * time.Second)
	if err := os.WriteFile(conf, []byte("nameserver "+topo.Server6b.String()+"\n"), 0o644); err != nil {
		e.T.Fatalf("%v", err)
	}
	for name, want := range map[string]engine.LineID{"alpha": "a", "bravo": "b", "charlie": "c"} {
		var s Stream
		streams[name].WaitJSON(e, 20*time.Second, &s)
		e.CheckStreamSurvived(name+"'s stream across two DNS changes", s, want)
	}
	e.ExpectTCP("bravo's new connections after the DNS changes", "bravo", AsUser, "b", topo.Server4, 3)
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
	err := e.Eng.Cleanup(e.Ctx())
	e.T.Check(err == nil, "cleanup after the crash succeeds (%v)", err)
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

// reducedPath makes line c's router a smaller hop and proves the setting took.
func (e *Env) reducedPath(mtu int) {
	if err := e.Net.SetPathMTU(e.Ctx(), "c", mtu); err != nil {
		e.T.Fatalf("mtu: %v", err)
	}
	routes, err := e.Net.PathMTU(e.Ctx(), "c")
	if err != nil {
		e.T.Fatalf("%v", err)
	}
	want := strconv.Itoa(mtu)
	good := 0
	for _, v := range routes {
		if v == want {
			good++
		}
	}
	e.T.Require(len(routes) == 4 && good == 4, "line c's router forwards at most %d bytes both ways, IPv4 and IPv6 (%v)", mtu, routes)
}

// serverLearnedMTU is the path MTU the fake internet learned towards an
// address on the PC (0 when none).
func (e *Env) serverLearnedMTU(server, pc netip.Addr) int {
	out, err := e.Net.R.IP(e.Ctx(), topo.INET, "route", "get", pc.String(), "from", server.String())
	if err != nil {
		e.T.Fatalf("%v", err)
	}
	if m := mtuPattern.FindStringSubmatch(out); m != nil {
		mtu, _ := strconv.Atoi(m[1])
		return mtu
	}
	return 0
}

func smallMTU(e *Env, mtu int) {
	e.reducedPath(mtu)
	cfg := e.DefaultConfig()
	cfg.Policy.IPv6 = true
	e.StartEngine(cfg)
	from := time.Now().UnixMilli()
	// Download first: the PC knows nothing yet and offers a full MSS, so the
	// server's big segments meet the hop and the server learns the path.
	// Then upload: the server still offers a full MSS (SetPathMTU fixes it),
	// so the PC's segments meet the hop and the PC learns it too.
	c := topo.Line("c")
	for _, fam := range []struct {
		name     string
		server   netip.Addr
		pc       netip.Addr
		download string
	}{{"IPv4", topo.Server4, c.Addr4.Addr(), "2097152"}, {"IPv6", topo.Server6, c.Addr6.Addr(), "1048576"}} {
		var up, down app.BulkResult
		e.RunJSON(Run{App: "charlie", Args: []string{"bulk", "--to", To(fam.server, wire.PortBulk), "--bytes", fam.download, "--timeout", "60000"}, Timeout: 90 * time.Second}, &down)
		e.T.Check(down.OK, "charlie's %s download over the %d-byte path arrives intact (%d bytes in %.0f ms, %s)", fam.name, mtu, down.Bytes, down.MS, down.Err)
		server := e.serverLearnedMTU(fam.server, fam.pc)
		e.T.Check(server > 0 && server <= mtu, "the server learned the %d-byte path towards %s from the download (%d)", mtu, fam.pc, server)
		e.RunJSON(Run{App: "charlie", Args: []string{"bulk", "--to", To(fam.server, wire.PortBulk), "--bytes", "1048576", "--timeout", "60000", "--upload"}, Timeout: 90 * time.Second}, &up)
		e.T.Check(up.OK, "charlie's %s 1 MiB upload over the %d-byte path arrives intact (%.0f ms, %s)", fam.name, mtu, up.MS, up.Err)
		learned := e.LearnedMTU(fam.server.String(), "c")
		e.T.Check(learned > 0 && learned <= mtu, "the PC learned the %d-byte path towards %s from the upload (%d)", mtu, fam.server, learned)
	}
	var mid, big app.DNSResult
	e.RunJSON(Run{App: "charlie", Args: []string{"dns", "--server", To(topo.Server4, wire.PortDNS), "--name", "mid.test", "--type", "TXT", "--edns", "4096"}}, &mid)
	e.T.Check(mid.Err == "" && !mid.UDPTruncated && mid.TXTBytes == wire.MidTXTBytes,
		"a %d-byte DNS answer over UDP (fragmented on this path) arrives whole (%d TXT bytes, truncated %v, %s)", mid.Size, mid.TXTBytes, mid.UDPTruncated, mid.Err)
	e.RunJSON(Run{App: "charlie", Args: []string{"dns", "--server", To(topo.Server4, wire.PortDNS), "--name", "big.test", "--type", "TXT", "--edns", "1232"}}, &big)
	e.T.Check(big.Err == "" && big.UDPTruncated && big.TCPFallback && big.TXTBytes == wire.BigTXTBytes,
		"a %d-byte DNS answer is truncated over UDP and arrives over TCP (%d TXT bytes, %s)", big.Size, big.TXTBytes, big.Err)
	// Where it all went, as the servers saw it: every transfer and query
	// over line c, the reduced path.
	recs := Select(e.Records(), func(r inet.Record) bool { return r.T >= from })
	bulk := Select(recs, func(r inet.Record) bool {
		return r.Kind == "tcp" && strings.HasSuffix(r.Dst, ":"+strconv.Itoa(wire.PortBulk))
	})
	dns := Select(recs, func(r inet.Record) bool { return r.Kind == "dns" && strings.HasSuffix(r.Data, "/16") })
	e.T.Check(len(bulk) == 4 && RecordLines(bulk)["c"] == 4, "the servers saw all 4 transfers arrive over line c (%d transfers, lines %s)", len(bulk), Describe(RecordLines(bulk)))
	e.T.Check(len(dns) == 3 && RecordLines(dns)["c"] == 3, "the DNS server saw the UDP and TCP queries arrive over line c (%d queries, lines %s)", len(dns), Describe(RecordLines(dns)))
}

func bigUDP(e *Env) {
	e.reducedPath(1280)
	cfg := e.DefaultConfig()
	cfg.Policy.IPv6 = true
	e.StartEngine(cfg)
	small := e.UDP("charlie", AsUser, "--to", To(topo.Server4, wire.PortUDPEcho), "--count", "5", "--size", "200")
	e.T.Require(small.Received == 5 && Lines(small.Seen)["c"] == 5, "small datagrams on c are answered (%d of 5)", small.Received)
	_, recorded := e.WaitRecords(2*time.Second, func(recs []inet.Record) bool { return len(Select(recs, Tagged("udp", small.Token))) == 5 })
	e.T.Require(recorded, "the server recorded the 5 small datagrams")
	var got []string
	ok := true
	for _, server := range []netip.Addr{topo.Server4, topo.Server6} {
		// Warm-up: IPv6 only fragments at the source, so each end loses its
		// first big datagram while it learns the path. Then every one counts.
		e.UDP("charlie", AsUser, "--to", To(server, wire.PortUDPEcho), "--count", "3", "--size", "1400", "--interval", "200")
		u := e.UDP("charlie", AsUser, "--to", To(server, wire.PortUDPEcho), "--count", "6", "--size", "1400", "--interval", "200")
		lines := Lines(u.Seen)
		ok = ok && u.Received == u.Sent && lines["c"] == u.Received
		got = append(got, fmt.Sprintf("%s: %d of %d answered, lines %s, errors %v", server, u.Received, u.Sent, Describe(lines), u.SendErrors))
	}
	e.T.Expect(ok, "1400-byte datagrams without DF over a 1280-byte path all get through once the path is known, all on c (%s)", strings.Join(got, "; "))
}

func dfTooBig(e *Env) {
	e.reducedPath(1280)
	cfg := e.DefaultConfig()
	cfg.Policy.IPv6 = true
	e.StartEngine(cfg)
	control := e.UDP("charlie", AsUser, "--to", To(topo.Server4, wire.PortUDPEcho), "--connect", "--df", "--count", "5", "--size", "200")
	e.T.Require(control.Received == 5, "small don't-fragment datagrams are answered (%d of 5)", control.Received)
	_, recorded := e.WaitRecords(2*time.Second, func(recs []inet.Record) bool { return len(Select(recs, Tagged("udp", control.Token))) == 5 })
	e.T.Require(recorded, "the server recorded the 5 small don't-fragment datagrams")
	var got []string
	ok := true
	for _, server := range []netip.Addr{topo.Server4, topo.Server6} {
		u := e.UDP("charlie", AsUser, "--to", To(server, wire.PortUDPEcho), "--connect", "--df", "--count", "6", "--size", "1400", "--interval", "300")
		told := u.SendErrors["EMSGSIZE"] + u.RecvErrors["EMSGSIZE"]
		e.Sleep(500 * time.Millisecond)
		escaped := len(Select(e.Records(), Tagged("udp", u.Token)))
		ok = ok && told > 0 && escaped == 0
		got = append(got, fmt.Sprintf("%s: EMSGSIZE %d times, %d of %d reached the server", server, told, escaped, u.Sent))
	}
	e.T.Expect(ok, "1400-byte don't-fragment datagrams over a 1280-byte path are reported too big and none gets out (%s)", strings.Join(got, "; "))
}
