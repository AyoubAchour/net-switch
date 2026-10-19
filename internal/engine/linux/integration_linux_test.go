//go:build linux

package linux

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/journal"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// CI invokes this binary under unshare --net. These mutations must never run
// in a developer's network namespace as part of ordinary go test.
func TestKernelPlatform(t *testing.T) {
	if os.Getenv("NETSWITCH_ISOLATED_NETNS") != "1" {
		t.Skip("requires CI's isolated network namespace")
	}
	if os.Geteuid() != 0 {
		t.Fatal("isolated kernel test requires root")
	}
	selfNS, _ := os.Readlink("/proc/self/ns/net")
	initNS, _ := os.Readlink("/proc/1/ns/net")
	if selfNS == "" || selfNS == initNS {
		t.Fatal("refusing kernel mutations in the initial network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
	p, err := New(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	tun, err := p.OpenTun(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()

	t.Run("TunWriteAndOrderedReader", func(t *testing.T) {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("198.18.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		remote := netip.MustParseAddrPort("198.18.0.2:12345")
		local := c.LocalAddr().(*net.UDPAddr).AddrPort()
		if err := tun.WritePacket(ctx, packet.UDP(remote, local, []byte("kernel-reply"))); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 9000)
		n, _, err := c.ReadFromUDP(buf)
		if err != nil || string(buf[:n]) != "kernel-reply" {
			t.Fatalf("TUN reply: %q %v", buf[:n], err)
		}
		for i := 0; i < 100; i++ {
			if _, err := c.WriteToUDPAddrPort([]byte{byte(i)}, remote); err != nil {
				t.Fatal(err)
			}
			var n int
			for {
				n, err = tun.ReadPacket(ctx, buf)
				if err != nil {
					t.Fatal(err)
				}
				if n >= 29 && buf[0]>>4 == 4 && buf[9] == 17 {
					break
				}
				t.Logf("unrelated kernel control packet before UDP %d: %x", i, buf[:min(n, 48)])
			}
			if n < 29 || buf[n-1] != byte(i) {
				t.Fatalf("packet order: got %x at %d", buf[:n], i)
			}
		}
		raw, err := p.objects.tun.device.File().SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var flags uint16
		var optionErr error
		if err := raw.Control(func(fd uintptr) {
			ifr, e := unix.NewIfreq(p.tunSpec.Name)
			if e != nil {
				optionErr = e
				return
			}
			optionErr = unix.IoctlIfreq(int(fd), unix.TUNGETIFF, ifr)
			flags = ifr.Uint16()
		}); err != nil {
			t.Fatal(err)
		}
		if optionErr != nil || flags&unix.IFF_MULTI_QUEUE != 0 || flags&unix.IFF_VNET_HDR == 0 {
			t.Fatalf("ordered offload flags %#x: %v", flags, optionErr)
		}
	})

	t.Run("RuleActionFingerprint", func(t *testing.T) {
		r := netlink.NewRule()
		r.Family = unix.AF_INET
		r.Priority = 17500
		r.Table = 22000
		r.Type = 1
		r.Protocol = routeProtocol
		r.Mark = 0x4e53ffff
		mask := ^uint32(0)
		r.Mask = &mask
		fp := ruleFP(p.objects, *r)
		if err := p.journal.Create(ctx, "rule", fp); err != nil {
			t.Fatal(err)
		}
		d := objectDriver{p.objects, "rule"}
		if _, found, err := d.Inspect(ctx, fp); err != nil || !found {
			t.Fatalf("live rule did not roundtrip: found %v, %v", found, err)
		}
		if err := netlink.RuleDel(r); err != nil {
			t.Fatal(err)
		}
		r.Type = unix.RTN_PROHIBIT
		r.Table = 0
		if err := netlink.RuleAdd(r); err != nil {
			t.Fatal(err)
		}
		defer netlink.RuleDel(r)
		if err := p.journal.Remove(ctx, "rule", fp); err != nil {
			t.Fatal(err)
		}
		views, err := readRules(ctx, unix.AF_INET)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range views {
			if v.rule.Priority == r.Priority && v.rule.Type == r.Type {
				return
			}
		}
		t.Fatal("cleanup removed another tool's replacement action")
	})

	t.Run("RouteFingerprintAndIntentRecovery", func(t *testing.T) {
		for _, fam := range []int{unix.AF_INET, unix.AF_INET6} {
			r := netlink.Route{Family: fam, Table: 22010, Type: unix.RTN_UNREACHABLE, Dst: prefix(defaultCIDR(fam)), Protocol: routeProtocol, Priority: int(^uint32(0))}
			if fam == unix.AF_INET6 {
				r.LinkIndex = lo.Attrs().Index
			}
			fp := routeFP(p.objects, r)
			if err := p.journal.Create(ctx, "route", fp); err != nil {
				t.Fatal(err)
			}
			d := objectDriver{p.objects, "route"}
			if _, found, err := d.Inspect(ctx, fp); err != nil || !found {
				live, _ := netlink.RouteListFiltered(fam, &netlink.Route{Table: r.Table}, netlink.RT_FILTER_TABLE)
				t.Fatalf("route fingerprint: found %v, %v; wanted %+v live %+v", found, err, r, live)
			}
			if err := p.journal.Remove(ctx, "route", fp); err != nil {
				t.Fatal(err)
			}
			if _, found, _ := d.Inspect(ctx, fp); found {
				t.Fatal("owned route remained")
			}
		}
		// Stop after the syscall but before the created mark. A fresh recovery
		// session must still remove this complete, matching intent.
		dir := filepath.Join(t.TempDir(), "recovery")
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		r := netlink.Route{Family: unix.AF_INET, Table: 22011, Type: unix.RTN_UNREACHABLE, Dst: prefix("203.0.113.200/32"), Protocol: routeProtocol}
		store := diskStore{filepath.Join(dir, "engine-journal.json")}
		if err := store.Append(journal.Record{ID: "torn-creation", Boot: p.objects.boot, Instance: "exited", Kind: "route", Fingerprint: routeFP(p.objects, r), Phase: "intent"}); err != nil {
			t.Fatal(err)
		}
		if err := netlink.RouteAdd(&r); err != nil {
			t.Fatal(err)
		}
		recovered, err := New(ctx, dir)
		if err != nil {
			t.Fatal(err)
		}
		recovered.Close()
		if _, found, _ := (objectDriver{p.objects, "route"}).Inspect(ctx, routeFP(p.objects, r)); found {
			t.Fatal("intent recovery left the route")
		}
	})

	t.Run("BoundUDPErrorQueue", func(t *testing.T) {
		link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "test-line", MTU: 1280}}
		if err := netlink.LinkAdd(link); err != nil {
			t.Fatal(err)
		}
		defer netlink.LinkDel(link)
		if err := netlink.LinkSetUp(link); err != nil {
			t.Fatal(err)
		}
		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: prefix("192.0.2.1/24")}); err != nil {
			t.Fatal(err)
		}
		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: prefix("192.0.2.42/24")}); err != nil {
			t.Fatal(err)
		}
		def := netlink.Route{LinkIndex: link.Index, Family: unix.AF_INET, Dst: prefix("0.0.0.0/0"), Scope: netlink.SCOPE_LINK, Table: unix.RT_TABLE_MAIN, Type: unix.RTN_UNICAST}
		def.Src = net.ParseIP("192.0.2.42")
		if err := netlink.RouteAdd(&def); err != nil {
			t.Fatal(err)
		}
		if err := p.Prepare(ctx, []platform.Line{{ID: "test", Interface: link.Name}}); err != nil {
			t.Fatal(err)
		}
		sock, err := p.OpenUDP(ctx, "test", false)
		if err != nil {
			t.Fatal(err)
		}
		defer sock.Close()
		if got := sock.LocalAddr().Addr(); got != netip.MustParseAddr("192.0.2.42") {
			t.Fatalf("source selection ignored the kernel's preferred source: %s", got)
		}
		_, err = sock.WriteTo(make([]byte, 1400), netip.MustParseAddrPort("198.51.100.1:30000"), true)
		var big *platform.TooBig
		if !errors.As(err, &big) || big.MTU != 1280 {
			t.Fatalf("real EMSGSIZE must carry path MTU 1280: %v", err)
		}
		// The receive goroutine may drain the queue before WriteTo handles
		// EMSGSIZE. The path MTU must survive that ordering, per destination.
		u := sock.(*udpSocket)
		u.drainErrors()
		if big := u.tooBig(netip.MustParseAddrPort("198.51.100.1:30000")); big.MTU != 1280 {
			t.Fatalf("drained error queue lost the path MTU: %+v", big)
		}
		if err := netlink.RouteDel(&def); err != nil {
			t.Fatal(err)
		}
		p.mu.Lock()
		err = p.reconcileLocked(ctx)
		p.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if c, err := p.OpenUDP(ctx, "test", false); err == nil {
			c.Close()
			t.Fatal("lost default route got an unbound fallback")
		}
	})
}
