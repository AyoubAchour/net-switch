//go:build linux

package linux

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/journal"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type pausedJournal struct {
	diskStore
	paused          atomic.Bool
	started, resume chan struct{}
	once            sync.Once
}

func (s *pausedJournal) Append(r journal.Record) error {
	if s.paused.Load() {
		s.once.Do(func() { close(s.started); <-s.resume })
	}
	return s.diskStore.Append(r)
}

func TestKernelReconcileDoesNotBlockDials(t *testing.T) {
	requireKernelNamespace(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
	def := netlink.Route{Family: unix.AF_INET, LinkIndex: lo.Attrs().Index, Dst: prefix("0.0.0.0/0"), Table: unix.RT_TABLE_MAIN, Scope: netlink.SCOPE_LINK, Type: unix.RTN_UNICAST}
	if err := netlink.RouteAdd(&def); err != nil {
		t.Fatal(err)
	}
	defer netlink.RouteDel(&def)
	dir := filepath.Join(t.TempDir(), "state")
	p, err := New(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := p.OpenTun(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.Prepare(ctx, []platform.Line{{ID: "loop", Interface: "lo"}}); err != nil {
		t.Fatal(err)
	}
	// Replace only the storage adapter. All kernel reconciliation, journal
	// ordering and the actual bound TCP dial below are production code.
	if err := p.journal.Close(); err != nil {
		t.Fatal(err)
	}
	store := &pausedJournal{diskStore: diskStore{filepath.Join(dir, "engine-journal.json")}, started: make(chan struct{}), resume: make(chan struct{})}
	j := &journal.Journal{Store: store, Lock: fileLock{filepath.Join(dir, "engine.lock")}, Kinds: map[string]journal.Object{}}
	for _, kind := range []string{"tun", "address", "route", "rule", "binding"} {
		j.Kinds[kind] = objectDriver{p.objects, kind}
	}
	p.journal, err = j.Open(ctx, p.objects.boot, p.Instance)
	if err != nil {
		t.Fatal(err)
	}
	addr := &netlink.Addr{IPNet: prefix("127.0.0.42/32"), Scope: int(netlink.SCOPE_HOST), Broadcast: net.IPv4zero}
	if err := netlink.AddrAdd(lo, addr); err != nil {
		t.Fatal(err)
	}
	defer netlink.AddrDel(lo, addr)
	store.paused.Store(true)
	var resume sync.Once
	defer resume.Do(func() { close(store.resume) })
	reconciled := make(chan error, 1)
	go func() { p.routeMu.Lock(); err := p.reconcileLocked(ctx); p.routeMu.Unlock(); reconciled <- err }()
	select {
	case <-store.started:
	case <-ctx.Done():
		t.Fatal("journal did not actually stall")
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan error, 1)
	go func() {
		for range 10 {
			c, err := listener.Accept()
			if err != nil {
				accepted <- err
				return
			}
			c.Close()
		}
		accepted <- nil
	}()
	dials := make(chan error, 1)
	start := time.Now()
	go func() {
		for range 10 {
			c, err := p.DialTCP(ctx, "loop", listener.Addr().(*net.TCPAddr).AddrPort())
			if err != nil {
				dials <- err
				return
			}
			c.Close()
		}
		dials <- nil
	}()
	select {
	case err := <-dials:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("bound dials waited for journal I/O")
	}
	t.Logf("10 bound kernel TCP dials during a blocked reconciliation: %s", time.Since(start))
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
	resume.Do(func() { close(store.resume) })
	if err := <-reconciled; err != nil {
		t.Fatal(err)
	}
}

func TestKernelMonitorRepairsRulesRoutesAndReplug(t *testing.T) {
	requireKernelNamespace(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dir := filepath.Join(t.TempDir(), "state")
	p, err := New(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := p.OpenTun(ctx); err != nil {
		t.Fatal(err)
	}
	makeLine := func() *netlink.Dummy {
		l := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "repair-line"}}
		if err := netlink.LinkAdd(l); err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetUp(l); err != nil {
			t.Fatal(err)
		}
		if err := netlink.AddrAdd(l, &netlink.Addr{IPNet: prefix("192.0.2.1/24")}); err != nil {
			t.Fatal(err)
		}
		def := netlink.Route{Family: unix.AF_INET, LinkIndex: l.Index, Table: unix.RT_TABLE_MAIN, Dst: prefix("0.0.0.0/0"), Type: unix.RTN_UNICAST, Scope: netlink.SCOPE_LINK}
		if err := netlink.RouteAdd(&def); err != nil {
			t.Fatal(err)
		}
		return l
	}
	line := makeLine()
	defer func() { netlink.LinkDel(line) }()
	if err := p.Prepare(ctx, []platform.Line{{ID: "line", Interface: line.Name}}); err != nil {
		t.Fatal(err)
	}
	fatal := make(chan error, 1)
	p.Fatal = func(err error) {
		select {
		case fatal <- err:
		default:
		}
	}
	if err := p.Capture(ctx); err != nil {
		t.Fatal(err)
	}
	p.routeMu.Lock()
	var removed []ownedObject
	for _, o := range p.owned {
		if o.kind != "rule" && o.kind != "route" {
			continue
		}
		removed = append(removed, o)
		if err := (objectDriver{p.objects, o.kind}).Remove(ctx, o.fp); err != nil {
			p.routeMu.Unlock()
			t.Fatal(err)
		}
		if _, found, err := (objectDriver{p.objects, o.kind}).Inspect(ctx, o.fp); err != nil || found {
			p.routeMu.Unlock()
			t.Fatalf("fixture was not removed: %v %v", found, err)
		}
	}
	p.routeMu.Unlock()
	if len(removed) < 10 {
		t.Fatalf("too few real objects tested: %d", len(removed))
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		all := true
		for _, o := range removed {
			_, found, err := (objectDriver{p.objects, o.kind}).Inspect(ctx, o.fp)
			if err != nil || !found {
				all = false
				break
			}
		}
		if all {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("monitor did not restore missing rules and routes")
		}
		time.Sleep(20 * time.Millisecond)
	}
	before := line.Index
	if err := netlink.LinkDel(line); err != nil {
		t.Fatal(err)
	}
	line = makeLine()
	if line.Index == before {
		t.Fatal("replug fixture did not change ifindex")
	}
	deadline = time.Now().Add(3 * time.Second)
	for {
		binding, err := p.binding("line", false)
		if err == nil && binding.Index == line.Index {
			break
		}
		select {
		case err := <-fatal:
			t.Fatal(err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("same revision did not recover replug: %+v %v", binding, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := p.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	records, err := (diskStore{filepath.Join(dir, "engine-journal.json")}).Records()
	if err != nil || len(records) != 0 {
		t.Fatalf("cleanup did not compact journal: %d %v", len(records), err)
	}
}

func TestKernelIPv6DisabledStartsIPv4Only(t *testing.T) {
	requireKernelNamespace(t)
	const path = "/proc/sys/net/ipv6/conf/default/disable_ipv6"
	old, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	defer os.WriteFile(path, old, 0600)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p, err := New(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := p.OpenTun(ctx); err != nil {
		t.Fatal(err)
	}
	if !p.ipv4Only {
		t.Fatal("disabled IPv6 was not detected on the new TUN")
	}
	if err := p.Prepare(ctx, []platform.Line{{ID: "loop", Interface: "lo"}}); err != nil {
		t.Fatal(err)
	}
	if err := p.Capture(ctx); err != nil {
		t.Fatal(err)
	}
	p.routeMu.Lock()
	defer p.routeMu.Unlock()
	for _, o := range p.owned {
		var family struct{ Family int }
		if err := json.Unmarshal([]byte(o.fp["object"]), &family); err != nil {
			t.Fatal(err)
		}
		if family.Family == unix.AF_INET6 {
			t.Fatal("created IPv6 routing object on IPv4-only host")
		}
	}
}
