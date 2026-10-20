//go:build linux

package linux

import (
	"context"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
)

func TestKernelAmbiguousAddressDisablesOnlyItsLine(t *testing.T) {
	requireKernelNamespace(t)
	ctx := context.Background()
	makeLine := func(name, address string, metric int) *netlink.Dummy {
		l := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
		if err := netlink.LinkAdd(l); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { netlink.LinkDel(l) })
		if err := netlink.LinkSetUp(l); err != nil {
			t.Fatal(err)
		}
		if err := netlink.AddrAdd(l, &netlink.Addr{IPNet: prefix(address)}); err != nil {
			t.Fatal(err)
		}
		if err := netlink.RouteAdd(&netlink.Route{Family: unix.AF_INET, LinkIndex: l.Index, Table: unix.RT_TABLE_MAIN, Dst: prefix("0.0.0.0/0"), Type: unix.RTN_UNICAST, Scope: netlink.SCOPE_LINK, Priority: metric}); err != nil {
			t.Fatal(err)
		}
		return l
	}
	a := makeLine("amb-a", "192.0.2.1/24", 10)
	b := makeLine("amb-b", "198.51.100.1/24", 20)
	p, err := New(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err = p.OpenTun(ctx); err != nil {
		t.Fatal(err)
	}
	if err = p.Prepare(ctx, []platform.Line{{ID: "a", Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}, {ID: "b", Interface: b.Name}}); err != nil {
		t.Fatal(err)
	}
	if _, err = p.binding("a", false); err != nil {
		t.Fatal("fixture a unavailable", err)
	}
	duplicate := &netlink.Addr{IPNet: prefix("192.0.2.1/32")}
	if err = netlink.AddrAdd(b, duplicate); err != nil {
		t.Fatal(err)
	}
	if err = p.reconcileLocked(ctx); err != nil {
		t.Fatal("one ambiguous line failed the whole engine", err)
	}
	if _, err = p.binding("a", false); err == nil || !strings.Contains(err.Error(), "multiple interfaces") {
		t.Fatal("ambiguous line stayed usable", err)
	}
	if got, err := p.binding("b", false); err != nil || got.Index != b.Index {
		t.Fatal("healthy line lost routing", err)
	} else {
		routes, err := netlink.RouteGetWithOptions(net.IPv4(203, 0, 113, 99), &netlink.RouteGetOptions{OifIndex: b.Index, Mark: got.Mark})
		if err != nil || len(routes) == 0 || routes[0].LinkIndex != b.Index {
			t.Fatalf("healthy line's real marked route was lost: %v %v", routes, err)
		}
	}
	if err = netlink.AddrDel(b, duplicate); err != nil {
		t.Fatal(err)
	}
	if err = p.reconcileLocked(ctx); err != nil {
		t.Fatal(err)
	}
	if got, err := p.binding("a", false); err != nil || got.Index != a.Index {
		t.Fatal("line did not recover", err)
	}
	if err = netlink.AddrAdd(b, duplicate); err != nil {
		t.Fatal(err)
	}
	if err = netlink.LinkSetDown(b); err != nil {
		t.Fatal(err)
	}
	if err = p.reconcileLocked(ctx); err == nil {
		t.Fatal("no usable line did not fail open")
	}
}
