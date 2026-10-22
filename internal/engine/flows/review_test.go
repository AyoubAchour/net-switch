package flows

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
)

var ownerForReview = platform.Owner{AppID: "review"}

func TestDefaultsAdmitTwoThousandTCPFlows(t *testing.T) {
	f := table(t, Defaults())
	for i := range 2000 {
		x, err := f.Begin("tcp", tuple)
		if err != nil {
			t.Fatalf("flow %d: %v", i+1, err)
		}
		if _, err := x.Resolve(ownerForReview); err != nil {
			t.Fatal(err)
		}
		x.Established(tuple.Source.Addr())
		defer x.Close()
		if rx, tx := x.Buffers(); rx != 64<<10 || tx != 64<<10 {
			t.Errorf("flow %d starts above floor: %d/%d", i+1, rx, tx)
			return
		}
	}
	if g := f.Stats(); g.Flows != 2000 || g.TCPBytes != 0 {
		t.Fatal(g)
	}
}

func TestTCPGrowthReturnsToFloorAndAdmissionSurvivesExhaustion(t *testing.T) {
	l := Defaults()
	l.TCPBytes = 2 * MinTCP
	f := table(t, l)
	x := admit(t, f, "tcp", "first").(*ticket)
	defer x.Close()
	if !x.Grow(2*MinTCP, 2*MinTCP) || f.Stats().TCPBytes != l.TCPBytes {
		t.Fatal("growth not reserved")
	}
	y := admit(t, f, "tcp", "second").(*ticket)
	defer y.Close()
	if y.Grow(2*MinTCP, MinTCP) {
		t.Fatal("growth exceeded budget")
	}
	x.Shrink(MinTCP, MinTCP)
	if f.Stats().TCPBytes != 0 || !y.Grow(2*MinTCP, MinTCP) {
		t.Fatal("idle grant was not reusable")
	}
}

func TestFullFlowLimitFitsFourSnapshots(t *testing.T) {
	f := table(t, Defaults())
	for i := range 65536 {
		x, err := f.Begin("tcp", tuple)
		if err != nil {
			t.Fatalf("flow %d: %v", i, err)
		}
		if _, err := x.Resolve(platform.Owner{AppID: fmt.Sprintf("app-%d", i/8192)}); err != nil {
			t.Fatal(err)
		}
		x.Established(tuple.Source.Addr())
	}
	for range 4 {
		p, err := f.Page("")
		if err != nil || p.Cursor == "" || len(p.Flows) != 64 {
			t.Fatal("full snapshot failed", err)
		}
	}
	if len(f.snapshots) != 4 {
		t.Fatal("four snapshots missing")
	}
	for _, s := range f.snapshots {
		if len(s.records) != 65536 {
			t.Fatal("snapshot truncated")
		}
	}
	t.Log("65536 real Table flows; all four snapshots retain all 65536 entries")
}

func TestIPv6RejectedBeforeOwnerLookup(t *testing.T) {
	f := table(t, Defaults())
	r := revision(2)
	r.Config.IPv6 = false
	r.Hash = policy.Hash(r.Config)
	f.Apply(r)
	_, err := f.Begin("tcp", platform.Tuple{Source: netip.MustParseAddrPort("[2001:db8::1]:3000"), Destination: netip.MustParseAddrPort("[2001:db8::2]:443")})
	if err != policy.ErrIPv6 || f.Stats().Flows != 0 {
		t.Fatal(err)
	}
}

func TestDoublePendingReleaseLogsWithoutPanic(t *testing.T) {
	f := table(t, Defaults())
	f.ReservePending(123)
	f.ReleasePending(123)
	f.ReleasePending(123)
	if g := f.Stats(); g.PendingBytes != 0 || g.DoubleReleases != 1 {
		t.Fatal(g)
	}
	select {
	case e := <-f.Events():
		if e.Type != "log" {
			t.Fatal(e)
		}
	default:
		t.Fatal("missing diagnostic")
	}
}

func TestWildcardUDPAddressRemovalMatchesOnlyItsLineAndFamily(t *testing.T) {
	f := New(Defaults(), nil)
	r := revision(1)
	r.Config.Combine = false
	r.Config.Lines[0].Addresses = []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}
	r.Config.Lines[1].Addresses = []netip.Addr{netip.MustParseAddr("192.0.2.2")}
	r.Hash = policy.Hash(r.Config)
	f.Apply(r)
	a := admit(t, f, "udp", "first")
	defer a.Close()
	a.Established(netip.IPv4Unspecified())
	b := admit(t, f, "udp", "pinned")
	defer b.Close()
	b.Established(netip.IPv4Unspecified())
	ctx, cancel := context.WithCancel(context.Background())
	a.SetCancel(cancel)
	for _, source := range []string{"192.0.2.2", "2001:db8::1"} {
		f.CloseFlows(Selector{Source: netip.MustParseAddr(source)}, 0)
		if ctx.Err() != nil {
			t.Fatal("other line/family closed IPv4")
		}
	}
	// Even a policy that already removed the address must find the old mapping.
	r.N++
	r.Config.Lines[0].Addresses = nil
	r.Hash = policy.Hash(r.Config)
	f.Apply(r)
	f.CloseFlows(Selector{Source: netip.MustParseAddr("192.0.2.1")}, 0)
	if ctx.Err() == nil {
		t.Fatal("wildcard UDP survived source removal")
	}
	if g := f.Stats(); g.UDPReadBytes != 0 || g.UDPAdapterBytes != 2*(8<<10) {
		t.Fatal("idle UDP sockets must account adapter storage without retaining receive buffers")
	}
}

// SYSTEM-DESIGN 5.7: two routers commonly hand out the same 192.168.1.x, so
// two lines can share a local address. Losing it on one line closes only that
// line's flows, by line and source together, for bound TCP and wildcard UDP.
func TestLineSourceClosureLeavesAnotherLineWithTheSameAddress(t *testing.T) {
	shared := netip.MustParseAddr("192.168.1.2")
	f := New(Defaults(), nil)
	r := revision(1)
	r.Config.Combine = false
	r.Config.Lines[0].Addresses = []netip.Addr{shared}
	r.Config.Lines[1].Addresses = []netip.Addr{shared}
	r.Hash = policy.Hash(r.Config)
	if _, err := f.Apply(r); err != nil {
		t.Fatal(err)
	}
	type flow struct {
		x      flowapi.Ticket
		ctx    context.Context
		line   string
		closes bool
	}
	var all []flow
	for _, c := range []struct {
		protocol, app string
		source        netip.Addr
		closes        bool
	}{
		{"tcp", "first", shared, true},                    // line A, bound to the lost address
		{"udp", "first", netip.IPv4Unspecified(), true},   // line A, wildcard UDP
		{"tcp", "pinned", shared, false},                  // line B, same address
		{"udp", "pinned", netip.IPv4Unspecified(), false}, // line B, wildcard UDP
	} {
		x := admit(t, f, c.protocol, c.app)
		defer x.Close()
		x.Established(c.source)
		ctx, cancel := context.WithCancel(context.Background())
		x.SetCancel(cancel)
		all = append(all, flow{x, ctx, map[string]string{"first": "A", "pinned": "B"}[c.app], c.closes})
	}
	if result := f.CloseLineSource("A", shared); result.Closed != 2 {
		t.Fatalf("closed %d flows on line A, want 2", result.Closed)
	}
	for i, x := range all {
		if closed := x.ctx.Err() != nil; closed != x.closes {
			t.Fatalf("flow %d on line %s: closed %t, want %t", i, x.line, closed, x.closes)
		}
	}
	if result := f.CloseLineSource("", shared); result.Closed != 0 {
		t.Fatal("a closure without a line closed flows")
	}
}

func TestAtomicCountersFoldExactlyOnce(t *testing.T) {
	f := table(t, Defaults())
	x := admit(t, f, "tcp", "known")
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 10000 {
				x.Add(1, 2)
			}
		})
	}
	wg.Wait()
	before := f.Totals().Apps["known"]
	x.Close()
	x.Close()
	if after := f.Totals().Apps["known"]; after != before || after.Up != 80000 || after.Down != 160000 {
		t.Fatal(before, after)
	}
}

type slowStore struct{ entered, release chan struct{} }

func (s *slowStore) SaveApplied(policy.Applied) error { close(s.entered); <-s.release; return nil }

func TestSlowFsyncDoesNotHoldPacketLock(t *testing.T) {
	f := table(t, Defaults())
	s := &slowStore{make(chan struct{}), make(chan struct{})}
	f.store = s
	apply := make(chan error, 1)
	go func() { _, err := f.Apply(revision(2)); apply <- err }()
	<-s.entered
	packets := make(chan struct{})
	go func() {
		x, err := f.Begin("tcp", tuple)
		if err == nil {
			x.Resolve(ownerForReview)
			x.Add(123, 456)
			x.Close()
		}
		if f.ReservePending(128) {
			f.ReleasePending(128)
		}
		close(packets)
	}()
	blocked := false
	select {
	case <-packets:
	case <-time.After(100 * time.Millisecond):
		blocked = true
	}
	close(s.release)
	if err := <-apply; err != nil {
		t.Fatal(err)
	}
	<-packets
	if blocked {
		t.Fatal("packet admission and accounting waited for fsync")
	}
}
