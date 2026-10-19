//go:build linux

// Package topo builds the fake PC and internet the Linux acceptance suite runs
// in, out of network namespaces, so the runner's own connection is never
// routed:
//
//	nsa-dut     the PC: the engine and the test apps, three lines
//	  eth-a ── nsa-ispa  home router, NAT    ── up-a ┐
//	  eth-b ── nsa-ispb  home router, NAT    ── up-b ├─ nsa-inet  the internet
//	  eth-c ── nsa-ispc  routed public /24   ── up-c ┘
//
// The internet and the line addresses use documentation ranges (192.0.2.0/24,
// 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32), never 10/8, 172.16/12 or
// 192.168/16, which Net Switch treats as local and leaves alone. The home
// routers' LANs are 192.168.1.0/24 and 192.168.2.0/24, as real ones are.
//
// Every server reports the source address it saw, and each line has its own:
// 192.0.2.1 is line a, 192.0.2.5 line b and 203.0.113.2 line c (line c isn't
// NATed, so unsolicited traffic can reach the PC, as STUN tests need). Each
// line's uplink is its own point-to-point link, so a smaller MTU or netem on
// one line leaves the others alone.
package topo

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/engine"
)

// Namespaces.
const (
	DUT  = "nsa-dut"
	INET = "nsa-inet"
	CTR  = "nsa-ctr"
)

// LineSpec is one line's addressing.
type LineSpec struct {
	ID    engine.LineID
	ISP   string // the router's namespace
	Iface string // the PC's interface
	// The PC's addresses and gateways on the line.
	Addr4 netip.Prefix
	GW4   netip.Addr
	Addr6 netip.Prefix
	GW6   netip.Addr
	// The router's uplink and the internet's end of it.
	WAN4, Core4 netip.Prefix
	WAN6, Core6 netip.Prefix
	// What servers see as the source for this line.
	Public4 netip.Addr
	Public6 netip.Prefix
	NAT     bool
	Metric  int
}

func p(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func a(s string) netip.Addr   { return netip.MustParseAddr(s) }

// Lines in priority order: a is the main line.
var Lines = []LineSpec{
	{
		ID: "a", ISP: "nsa-ispa", Iface: "eth-a",
		Addr4: p("192.168.1.2/24"), GW4: a("192.168.1.1"), Addr6: p("2001:db8:a::2/64"), GW6: a("2001:db8:a::1"),
		WAN4: p("192.0.2.1/30"), Core4: p("192.0.2.2/30"), WAN6: p("2001:db8:100:a::1/64"), Core6: p("2001:db8:100:a::fe/64"),
		Public4: a("192.0.2.1"), Public6: p("2001:db8:a::/64"), NAT: true, Metric: 100,
	},
	{
		ID: "b", ISP: "nsa-ispb", Iface: "eth-b",
		Addr4: p("192.168.2.2/24"), GW4: a("192.168.2.1"), Addr6: p("2001:db8:b::2/64"), GW6: a("2001:db8:b::1"),
		WAN4: p("192.0.2.5/30"), Core4: p("192.0.2.6/30"), WAN6: p("2001:db8:100:b::1/64"), Core6: p("2001:db8:100:b::fe/64"),
		Public4: a("192.0.2.5"), Public6: p("2001:db8:b::/64"), NAT: true, Metric: 200,
	},
	{
		ID: "c", ISP: "nsa-ispc", Iface: "eth-c",
		Addr4: p("203.0.113.2/24"), GW4: a("203.0.113.1"), Addr6: p("2001:db8:c::2/64"), GW6: a("2001:db8:c::1"),
		WAN4: p("192.0.2.9/30"), Core4: p("192.0.2.10/30"), WAN6: p("2001:db8:100:c::1/64"), Core6: p("2001:db8:100:c::fe/64"),
		Public4: a("203.0.113.2"), Public6: p("2001:db8:c::/64"), NAT: false, Metric: 300,
	},
}

// Line returns a line's spec.
func Line(id engine.LineID) LineSpec {
	for _, l := range Lines {
		if l.ID == id {
			return l
		}
	}
	panic("no line " + string(id))
}

// EngineLines is the line list an engine is started with.
func EngineLines() []engine.Line {
	out := make([]engine.Line, len(Lines))
	for i, l := range Lines {
		out[i] = engine.Line{ID: l.ID, Interface: l.Iface}
	}
	return out
}

// Servers on the fake internet.
var (
	Server4  = a("198.51.100.10") // every service
	Server4b = a("198.51.100.11") // the second STUN server
	Third4   = a("198.51.100.12") // never contacted by apps; answers pokes
	Server6  = a("2001:db8:100:1::10")
	Server6b = a("2001:db8:100:1::11")
)

// ManyServers are 50 more addresses running the UDP echo and whoami, for
// spreading flows over many destinations.
func ManyServers() []netip.Addr {
	out := make([]netip.Addr, 50)
	for i := range out {
		out[i] = netip.AddrFrom4([4]byte{198, 51, 100, byte(20 + i)})
	}
	return out
}

// LineOf maps the source a server saw to a line ("" when it's no line's).
func LineOf(seen netip.Addr) engine.LineID {
	seen = seen.Unmap()
	for _, l := range Lines {
		if seen == l.Public4 || l.Public6.Contains(seen) {
			return l.ID
		}
	}
	return ""
}

// LineOfText is LineOf for "ip" or "ip:port" text; "" when it doesn't parse.
func LineOfText(seen string) engine.LineID {
	if ap, err := netip.ParseAddrPort(seen); err == nil {
		return LineOf(ap.Addr())
	}
	if addr, err := netip.ParseAddr(seen); err == nil {
		return LineOf(addr)
	}
	return ""
}

// Net is a built topology.
type Net struct {
	R     *Runner
	dir   string
	self  string
	procs []*Process
}

var allNamespaces = []string{DUT, "nsa-ispa", "nsa-ispb", "nsa-ispc", INET, CTR}

// Up builds the topology and starts the fake internet's servers. self is this
// program (it serves with "serve"); dir collects logs.
func Up(ctx context.Context, self, dir string) (*Net, error) {
	logFile, err := os.Create(filepath.Join(dir, "topology.log"))
	if err != nil {
		return nil, err
	}
	n := &Net{R: NewRunner(logFile), dir: dir, self: self}
	n.Down(ctx)
	if err := n.build(ctx); err != nil {
		return n, err
	}
	return n, n.startServers(ctx)
}

func (n *Net) build(ctx context.Context) error {
	r := n.R
	for _, ns := range []string{DUT, "nsa-ispa", "nsa-ispb", "nsa-ispc", INET} {
		if _, err := r.Run(ctx, "ip", "netns", "add", ns); err != nil {
			return err
		}
		// No duplicate address detection or router adverts: addresses are
		// static and usable at once. Lines keep their IPv6 addresses while
		// down, as NetworkManager configures them.
		settings := []string{
			"net.ipv6.conf.all.accept_dad=0", "net.ipv6.conf.default.accept_dad=0",
			"net.ipv6.conf.all.accept_ra=0", "net.ipv6.conf.default.accept_ra=0",
			"net.ipv6.conf.all.keep_addr_on_down=1", "net.ipv6.conf.default.keep_addr_on_down=1",
		}
		if ns == DUT {
			// Ubuntu's defaults: loose reverse-path filtering, and pings
			// allowed for every group (unprivileged ICMP sockets).
			settings = append(settings,
				"net.ipv4.conf.all.rp_filter=2", "net.ipv4.conf.default.rp_filter=2",
				"net.ipv4.conf.all.promote_secondaries=1", "net.ipv4.conf.default.promote_secondaries=1",
				"net.ipv4.ping_group_range=0 2147483647")
		} else {
			settings = append(settings, "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1")
		}
		if err := r.Sysctl(ctx, ns, settings...); err != nil {
			return err
		}
		if _, err := r.IP(ctx, ns, "link", "set", "lo", "up"); err != nil {
			return err
		}
	}

	inet := []string{
		"link add srv0 type dummy",
		"link set srv0 up",
		"addr add 198.51.100.1/24 dev srv0",
		"addr add 2001:db8:100:1::1/64 dev srv0 nodad",
	}
	for _, addr := range append([]netip.Addr{Server4, Server4b, Third4}, ManyServers()...) {
		inet = append(inet, fmt.Sprintf("addr add %s/32 dev srv0", addr))
	}
	for _, addr := range []netip.Addr{Server6, Server6b} {
		inet = append(inet, fmt.Sprintf("addr add %s/128 dev srv0 nodad", addr))
	}
	if err := r.Batch(ctx, INET, inet); err != nil {
		return err
	}

	for _, l := range Lines {
		up := "up-" + string(l.ID)
		if _, err := r.Run(ctx, "ip", "link", "add", "wan", "netns", l.ISP, "type", "veth", "peer", "name", up, "netns", INET); err != nil {
			return err
		}
		if _, err := r.Run(ctx, "ip", "link", "add", l.Iface, "netns", DUT, "type", "veth", "peer", "name", "lan", "netns", l.ISP); err != nil {
			return err
		}
		isp := []string{
			"addr add " + l.WAN4.String() + " dev wan",
			"addr add " + l.WAN6.String() + " dev wan nodad",
			"addr add " + prefixOf(l.GW4, l.Addr4).String() + " dev lan",
			"addr add " + prefixOf(l.GW6, l.Addr6).String() + " dev lan nodad",
			// A fixed link-local address, so tests can reach the router by it.
			"addr add fe80::1/64 dev lan nodad",
			"link set wan up",
			"link set lan up",
			"route add default via " + l.Core4.Addr().String(),
			"route add default via " + l.Core6.Addr().String(),
		}
		if err := r.Batch(ctx, l.ISP, isp); err != nil {
			return err
		}
		core := []string{
			"addr add " + l.Core4.String() + " dev " + up,
			"addr add " + l.Core6.String() + " dev " + up + " nodad",
			"link set " + up + " up",
			"route add " + l.Public6.String() + " via " + l.WAN6.Addr().String(),
		}
		if !l.NAT {
			core = append(core, "route add "+l.Addr4.Masked().String()+" via "+l.WAN4.Addr().String())
		}
		if err := r.Batch(ctx, INET, core); err != nil {
			return err
		}
		if l.NAT {
			script := "table ip nat {\n chain post {\n  type nat hook postrouting priority 100; policy accept;\n  oifname \"wan\" masquerade\n }\n}\n"
			if err := r.Nft(ctx, l.ISP, script); err != nil {
				return err
			}
		}
		dut := []string{
			"addr add " + l.Addr4.String() + " dev " + l.Iface,
			"addr add " + l.Addr6.String() + " dev " + l.Iface + " nodad",
			"link set " + l.Iface + " up",
		}
		if err := r.Batch(ctx, DUT, dut); err != nil {
			return err
		}
		if err := n.AddDefault(ctx, l.ID); err != nil {
			return err
		}
	}
	return nil
}

// prefixOf is addr with the prefix length of on.
func prefixOf(addr netip.Addr, on netip.Prefix) netip.Prefix {
	return netip.PrefixFrom(addr, on.Bits())
}

func (n *Net) startServers(ctx context.Context) error {
	inetDir := filepath.Join(n.dir, "inet")
	if err := os.MkdirAll(inetDir, 0o755); err != nil {
		return err
	}
	proc, err := StartLogged(ctx, "fake internet", filepath.Join(inetDir, "serve.log"), "serving", 15*time.Second,
		"ip", "netns", "exec", INET, n.self, "serve", "--role", "inet", "--out", inetDir)
	if err != nil {
		return err
	}
	n.procs = append(n.procs, proc)
	for _, l := range Lines[:2] {
		proc, err := StartLogged(ctx, "router "+string(l.ID), filepath.Join(n.dir, "router-"+string(l.ID)+".log"), "serving", 15*time.Second,
			"ip", "netns", "exec", l.ISP, n.self, "serve", "--role", "lan")
		if err != nil {
			return err
		}
		n.procs = append(n.procs, proc)
	}
	return nil
}

// InetDir is where the fake internet writes what it observed.
func (n *Net) InetDir() string { return filepath.Join(n.dir, "inet") }

// Down stops every process in the namespaces and deletes them. It's safe to
// call on a half-built or already removed topology.
func (n *Net) Down(ctx context.Context) {
	for _, proc := range n.procs {
		proc.Stop()
	}
	n.procs = nil
	for _, ns := range allNamespaces {
		if _, err := os.Stat("/run/netns/" + ns); err != nil {
			continue
		}
		if out, err := n.R.Run(ctx, "ip", "netns", "pids", ns); err == nil {
			for _, field := range strings.Fields(out) {
				if pid, err := strconv.Atoi(field); err == nil && pid > 1 {
					if proc, err := os.FindProcess(pid); err == nil {
						_ = proc.Kill()
					}
				}
			}
		}
		_, _ = n.R.Run(ctx, "ip", "netns", "del", ns)
	}
	// Give the kernel a moment to release the interfaces.
	time.Sleep(200 * time.Millisecond)
}

// Leftovers lists namespaces of ours that still exist (after Down: none).
func Leftovers() []string {
	var out []string
	for _, ns := range allNamespaces {
		if _, err := os.Stat("/run/netns/" + ns); err == nil {
			out = append(out, ns)
		}
	}
	return out
}
