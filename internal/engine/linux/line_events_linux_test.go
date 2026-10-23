//go:build linux

package linux

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"golang.org/x/sys/unix"
)

// SYSTEM-DESIGN 5.7, review of PR #46: two routers commonly hand out the
// same 192.168.1.x, so two lines can share a local address. When one line
// loses it, only that line's flows close, through the same handlers the
// service installs, for bound TCP and device-bound wildcard UDP alike.
func TestLineEventsCloseOnlyTheLineThatLostTheAddress(t *testing.T) {
	shared := netip.MustParseAddr("192.168.1.2")
	old := map[string]lineState{
		"a": {ID: "a", Index: 2, Up: true, Addresses: []netip.Addr{shared}},
		"b": {ID: "b", Index: 3, Up: true, Addresses: []netip.Addr{shared, netip.MustParseAddr("2001:db8::2")}},
	}
	current := map[string]lineState{
		"a": {ID: "a", Index: 2, Up: true, Addresses: []netip.Addr{shared}},
		"b": {ID: "b", Index: 3, Up: true, Addresses: []netip.Addr{netip.MustParseAddr("2001:db8::2")}},
	}
	down, removed := lineChanges(old, current)
	if len(down) != 0 || !slices.Equal(removed, []lineAddress{{"b", shared}}) {
		t.Fatalf("down %v, removed %v", down, removed)
	}

	table := flows.New(flows.Defaults(), nil)
	c := policy.Config{Lines: []platform.Line{{ID: "a", Addresses: []netip.Addr{shared}}, {ID: "b", Addresses: []netip.Addr{shared}}},
		Lanes: map[string]string{"a": "a", "b": "b"}, AppLines: map[string]string{"on-a": "a", "on-b": "b"}}
	if _, err := table.Apply(policy.Revision{N: 1, Hash: policy.Hash(c), Config: c}); err != nil {
		t.Fatal(err)
	}
	type flow struct {
		ctx    context.Context
		line   string
		closes bool
	}
	var all []flow
	for _, f := range []struct {
		protocol, app string
		source        netip.Addr
	}{{"tcp", "on-a", shared}, {"udp", "on-a", netip.IPv4Unspecified()}, {"tcp", "on-b", shared}, {"udp", "on-b", netip.IPv4Unspecified()}} {
		x, err := table.Begin(f.protocol, platform.Tuple{Source: netip.MustParseAddrPort("198.18.0.2:40000"), Destination: netip.MustParseAddrPort("203.0.113.7:443")})
		if err != nil {
			t.Fatal(err)
		}
		defer func(x flowapi.Ticket) { x.Close() }(x)
		d, err := x.Resolve(platform.Owner{AppID: f.app})
		if err != nil {
			t.Fatal(err)
		}
		x.Established(f.source)
		ctx, cancel := context.WithCancel(context.Background())
		x.SetCancel(cancel)
		all = append(all, flow{ctx, d.Line, d.Line == "b"})
	}
	lineDown, addressRemoved := lineEvents(table)
	for _, a := range removed {
		addressRemoved(a.Line, a.Address)
	}
	for i, f := range all {
		if closed := f.ctx.Err() != nil; closed != f.closes {
			t.Fatalf("flow %d on line %s: closed %t, want %t", i, f.line, closed, f.closes)
		}
	}
	lineDown("a")
	for i, f := range all {
		if f.ctx.Err() == nil {
			t.Fatalf("flow %d on line %s survived its line going down", i, f.line)
		}
	}
}

// Linux reports an IPv6 address going deprecated (IFA_F_DEPRECATED) as still
// present, so its flows stay until it is actually removed; a tentative one is
// not usable yet. So Linux needs no preferred/valid split: the kernel itself
// avoids deprecated sources for new connections (RFC 6724 rule 3).
func TestDeprecatedAddressesStayOnTheirLine(t *testing.T) {
	v6 := netip.MustParseAddr("2001:db8::10")
	for _, c := range []struct {
		flags  int
		usable bool
	}{
		{0, true},
		{unix.IFA_F_DEPRECATED, true},
		{unix.IFA_F_TENTATIVE, false},
		{unix.IFA_F_DADFAILED, false},
		{unix.IFA_F_DEPRECATED | unix.IFA_F_TENTATIVE, false},
	} {
		if got := usableAddress(c.flags, v6, false); got != c.usable {
			t.Fatalf("flags %#x: usable %t, want %t", c.flags, got, c.usable)
		}
	}
	if usableAddress(0, v6, true) || !usableAddress(0, netip.MustParseAddr("192.168.1.2"), true) {
		t.Fatal("IPv4-only lines keep IPv4 addresses only")
	}
	line := func(addresses ...netip.Addr) map[string]lineState {
		return map[string]lineState{"a": {ID: "a", Index: 2, Up: true, Addresses: addresses}}
	}
	if _, removed := lineChanges(line(v6), line(v6)); len(removed) != 0 {
		t.Fatalf("a deprecated address that is still listed was removed: %v", removed)
	}
	if _, removed := lineChanges(line(v6), line()); !slices.Equal(removed, []lineAddress{{"a", v6}}) {
		t.Fatalf("a removed address: %v", removed)
	}
}
