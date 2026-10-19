//go:build linux

// Package linux implements the engine's Linux boundary. It never shells out to
// ip, changes a firewall, or removes an object it cannot prove it owns.
package linux

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/journal"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const routeProtocol = 186

var bypass = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"}

type lineState struct {
	ID, Name           string
	Index, N, Table    int
	Mark               uint32
	Addresses          []netip.Addr
	Up                 bool
	Default4, Default6 bool
}
type Platform struct {
	mu                   sync.Mutex
	ctx                  context.Context
	Instance             string
	objects              *objects
	journal              *journal.Session
	base                 int
	allocated, capturing bool
	tunSpec              tunObject
	lines                map[string]lineState
	owned                map[string]ownedObject
	monitorCancel        context.CancelFunc
	monitorDone          chan struct{}
	Owners               *Owners
	// Callbacks run outside the platform lock.
	LineDown       func(string)
	AddressRemoved func(netip.Addr)
	Fatal          func(error)
	WrapTun        func(platform.TunDevice) platform.TunDevice
}
type ownedObject struct {
	kind string
	fp   journal.Fingerprint
}

func New(ctx context.Context, dir string) (*Platform, error) {
	if !filepath.IsAbs(dir) {
		return nil, errors.New("state directory must be absolute")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("state directory must be private (0700)")
	}
	boot, ns, err := namespaceIdentity()
	if err != nil {
		return nil, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	p := &Platform{ctx: ctx, Instance: hex.EncodeToString(nonce[:]), objects: &objects{boot: boot, netns: ns}, lines: map[string]lineState{}, owned: map[string]ownedObject{}}
	j := &journal.Journal{Store: diskStore{filepath.Join(dir, "engine-journal.json")}, Lock: fileLock{filepath.Join(dir, "engine.lock")}, Kinds: map[string]journal.Object{}}
	for _, kind := range []string{"tun", "address", "route", "rule", "binding"} {
		j.Kinds[kind] = objectDriver{p.objects, kind}
	}
	s, err := j.Open(ctx, boot, p.Instance)
	if err != nil {
		return nil, err
	}
	p.journal = s
	if err := s.Cleanup(ctx); err != nil {
		s.Close()
		return nil, fmt.Errorf("recover engine journal: %w", err)
	}
	p.Owners = NewOwners()
	return p, nil
}

func (p *Platform) Close() error {
	err := p.Cleanup(context.Background())
	return errors.Join(err, p.journal.Close())
}
func (p *Platform) OpenTun(ctx context.Context) (platform.TunDevice, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	links, err := retryDump(ctx, netlink.LinkList)
	if err != nil {
		return nil, err
	}
	index := 1
	for _, l := range links {
		index = max(index, l.Attrs().Index+1)
	}
	p.tunSpec = tunObject{Index: index, Name: "ns" + p.Instance[:10], Alias: "netswitch:" + p.Instance, MTU: 9000}
	if err := p.journal.Create(ctx, "tun", p.objects.fingerprint(p.tunSpec)); err != nil {
		return nil, err
	}
	for _, cidr := range []string{"198.18.0.1/30", "fdfe:dcba:9876::1/126"} {
		v := addressObject{index, p.tunSpec.Name, p.tunSpec.Alias, cidr}
		if err := p.journal.Create(ctx, "address", p.objects.fingerprint(v)); err != nil {
			p.objects.tun.Close()
			return nil, err
		}
	}
	if p.WrapTun != nil { return p.WrapTun(p.objects.tun), nil }
	return p.objects.tun, nil
}

func allRoutes(ctx context.Context) ([]netlink.Route, error) {
	return retryDump(ctx, func() ([]netlink.Route, error) {
		return netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{}, netlink.RT_FILTER_TABLE)
	})
}
func allRules(ctx context.Context) ([]netlink.Rule, error) {
	var all []netlink.Rule
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := readRules(ctx, family)
		if err != nil {
			return nil, err
		}
		for _,r := range rules { all = append(all,r.rule) }
	}
	return all, nil
}
func layoutAvailable(base, count int, rules []netlink.Rule, routes []netlink.Route) bool {
	for _, r := range rules {
		if r.Priority == base+9100 || r.Priority == base+12000 || (r.Priority > base+10000 && r.Priority <= base+10255) || (r.Priority > base+11000 && r.Priority <= base+11255) {
			return false
		}
		for n := 0; n <= count; n++ {
			if r.Table == 21000+base+n {
				return false
			}
		}
		if r.Mask != nil && *r.Mask != 0 && !r.Invert {
			for n := 1; n <= count; n++ {
				if (uint32(0x4e530000+base+n)^r.Mark)&*r.Mask == 0 {
					return false
				}
			}
		}
	}
	for _, r := range routes {
		if r.Table >= 21000+base && r.Table <= 21000+base+count {
			return false
		}
	}
	return true
}
func (p *Platform) allocate(ctx context.Context, count int) error {
	rules, err := allRules(ctx)
	if err != nil {
		return err
	}
	routes, err := allRoutes(ctx)
	if err != nil {
		return err
	}
	for base := 0; base+12000 < 32766; base += 1000 {
		if layoutAvailable(base, 255, rules, routes) {
			p.base = base
			p.allocated = true
			return nil
		}
	}
	return errors.New("no collision-free Linux rule/mark/table layout below main; routing remains off")
}

func (p *Platform) Prepare(ctx context.Context, lines []platform.Line) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(lines) == 0 || len(lines) > 255 {
		return errors.New("Linux routing needs 1–255 lines")
	}
	if !p.allocated {
		if err := p.allocate(ctx, len(lines)); err != nil {
			return err
		}
	}
	// Resolve every line before any mutation. Old line IDs retain their table
	// while existing flows use it; policy updates cannot relabel their sockets.
	next := make(map[string]lineState, len(p.lines)+len(lines))
	for id, l := range p.lines {
		next[id] = l
	}
	links, err := retryDump(ctx, netlink.LinkList)
	if err != nil {
		return err
	}
	for _, line := range lines {
		if _, ok := next[line.ID]; ok {
			continue
		}
		var match netlink.Link
		for _, link := range links {
			if line.Interface != "" {
				if link.Attrs().Name == line.Interface {
					match = link
				}
				continue
			}
			addrs, err := retryDump(ctx, func() ([]netlink.Addr, error) { return netlink.AddrList(link, netlink.FAMILY_ALL) })
			if err != nil {
				return err
			}
			for _, a := range addrs {
				ip, _ := netip.AddrFromSlice(a.IP)
				if slices.Contains(line.Addresses, ip.Unmap()) {
					if match != nil && match.Attrs().Index != link.Attrs().Index {
						return errors.New("ambiguous line interface")
					}
					match = link
				}
			}
		}
		if match == nil {
			return fmt.Errorf("line %s: interface not found", line.ID)
		}
		n := len(next) + 1
		if n > 255 {
			return errors.New("line allocation exhausted; restart required")
		}
		next[line.ID] = lineState{ID: line.ID, Name: match.Attrs().Name, Index: match.Attrs().Index, N: n, Table: 21000 + p.base + n, Mark: uint32(0x4e530000 + p.base + n)}
	}
	old := p.lines
	p.lines = next
	if err := p.reconcileLocked(ctx); err != nil {
		p.lines = old
		if p.capturing && p.Fatal != nil { go p.Fatal(fmt.Errorf("cannot reconcile line revision safely: %w",err)) }
		return err
	}
	return nil
}

func (p *Platform) add(ctx context.Context, kind string, fp journal.Fingerprint) error {
	key := kind + fp["object"]
	if _, ok := p.owned[key]; ok {
		return nil
	}
	if err := p.journal.Create(ctx, kind, fp); err != nil {
		return err
	}
	p.owned[key] = ownedObject{kind, fp}
	return nil
}
func (p *Platform) reconcileLocked(ctx context.Context) error {
	routes, err := allRoutes(ctx)
	if err != nil {
		return err
	}
	desired := map[string]ownedObject{}
	keep := func(kind string, fp journal.Fingerprint) error {
		desired[kind+fp["object"]] = ownedObject{kind, fp}
		return p.add(ctx, kind, fp)
	}
	// Fallback routes exist before every selector and never leave the table
	// during reconciliation, including when a DHCP default disappears.
	for _, l := range p.lines {
		for _, fam := range []int{unix.AF_INET, unix.AF_INET6} {
			r := netlink.Route{Family: fam, Table: l.Table, Dst: prefix(defaultCIDR(fam)), Type: unix.RTN_UNREACHABLE, Protocol: routeProtocol, Priority: int(^uint32(0))}
			if err := keep("route", routeFP(p.objects, r)); err != nil {
				return err
			}
		}
	}
	for id, l := range p.lines {
		link, err := netlink.LinkByIndex(l.Index)
		l.Up = false
		l.Default4 = false
		l.Default6 = false
		l.Addresses = nil
		if err != nil && !linkMissing(err) {
			return err
		}
		if err == nil && link.Attrs().Name == l.Name {
			l.Up = link.Attrs().Flags&net.FlagUp != 0
			addrs, err := retryDump(ctx, func() ([]netlink.Addr, error) { return netlink.AddrList(link, netlink.FAMILY_ALL) })
			if err != nil {
				return err
			}
			for _, a := range addrs {
				ip, ok := netip.AddrFromSlice(a.IP)
				if ok && a.Flags&unix.IFA_F_TENTATIVE == 0 {
					l.Addresses = append(l.Addresses, ip.Unmap())
				}
			}
		}
		for _, r := range routes {
			if !l.Up || r.LinkIndex != l.Index || r.Type != unix.RTN_UNICAST || r.Table == unix.RT_TABLE_LOCAL || (r.Table >= 21000+p.base && r.Table <= 21255+p.base) || r.Flags&unix.RTM_F_CLONED != 0 {
				continue
			}
			if r.Dst == nil || r.Dst.String() == defaultCIDR(r.Family) {
				if r.Family == unix.AF_INET6 {
					l.Default6 = true
				} else {
					l.Default4 = true
				}
			}
			r.Table = l.Table
			r.Protocol = routeProtocol
			r.Flags &^= unix.RTNH_F_LINKDOWN | unix.RTNH_F_DEAD
			if err := keep("route", routeFP(p.objects, r)); err != nil {
				return err
			}
		}
		binding := p.objects.fingerprint(struct {
			Line, Name string
			Index      int
			Mark       uint32
		}{id, l.Name, l.Index, l.Mark})
		if err := keep("binding", binding); err != nil {
			return err
		}
		for _, fam := range []int{unix.AF_INET, unix.AF_INET6} {
			r := netlink.NewRule()
			r.Family = fam
			r.Priority = p.base + 10000 + l.N
			r.Table = l.Table
			r.Mark = l.Mark
			mask := ^uint32(0)
			r.Mask = &mask
			r.Protocol = routeProtocol
			r.Type = 1
			if err := keep("rule", ruleFP(p.objects, *r)); err != nil {
				return err
			}
		}
		for _, ip := range l.Addresses {
			r := netlink.NewRule()
			r.Family = unix.AF_INET
			if ip.Is6() {
				r.Family = unix.AF_INET6
			}
			r.Priority = p.base + 11000 + l.N
			r.Table = l.Table
			r.Src = prefix(netip.PrefixFrom(ip, ip.BitLen()).String())
			r.Protocol = routeProtocol
			r.Type = 1
			if err := keep("rule", ruleFP(p.objects, *r)); err != nil {
				return err
			}
		}
		p.lines[id] = l
	}
	// New addresses select their table before old address selectors disappear.
	for _, kind := range []string{"rule", "route", "binding"} {
		for key, object := range p.owned {
			if object.kind != kind {
				continue
			}
			if _, ok := desired[key]; ok {
				continue
			}
			if err := p.journal.Remove(ctx, kind, object.fp); err != nil {
				return err
			}
			delete(p.owned, key)
		}
	}
	return nil
}

func (p *Platform) Capture(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.capturing {
		return nil
	}
	for _, cidr := range bypass {
		r := netlink.NewRule()
		r.Family = unix.AF_INET
		if prefix(cidr).IP.To4() == nil {
			r.Family = unix.AF_INET6
		}
		r.Priority = p.base + 9100
		r.Table = unix.RT_TABLE_MAIN
		r.Dst = prefix(cidr)
		r.Protocol = routeProtocol
		r.Type = 1
		if err := p.journal.Create(ctx, "rule", ruleFP(p.objects, *r)); err != nil {
			return err
		}
	}
	for _, fam := range []int{unix.AF_INET, unix.AF_INET6} {
		r := netlink.Route{Family: fam, Table: 21000 + p.base, LinkIndex: p.tunSpec.Index, Dst: prefix(defaultCIDR(fam)), Type: unix.RTN_UNICAST, Protocol: routeProtocol, Scope: netlink.SCOPE_LINK}
		if err := p.journal.Create(ctx, "route", routeFP(p.objects, r)); err != nil {
			return err
		}
	}
	for _, fam := range []int{unix.AF_INET, unix.AF_INET6} {
		r := netlink.NewRule()
		r.Family = fam
		r.Priority = p.base + 12000
		r.Table = 21000 + p.base
		r.IifName = "lo"
		r.Protocol = routeProtocol
		r.Type = 1
		if err := p.journal.Create(ctx, "rule", ruleFP(p.objects, *r)); err != nil {
			return err
		}
	}
	p.capturing = true
	run, cancel := context.WithCancel(p.ctx)
	p.monitorCancel = cancel
	p.monitorDone = make(chan struct{})
	go p.monitor(run, p.monitorDone)
	return nil
}
func (p *Platform) monitor(ctx context.Context, done chan struct{}) {
	defer close(done)
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		p.mu.Lock()
		old := make(map[string]lineState, len(p.lines))
		for id, l := range p.lines {
			old[id] = l
		}
		err := p.reconcileLocked(ctx)
		var down []string
		var removed []netip.Addr
		if err == nil {
			for id, before := range old {
				after := p.lines[id]
				if before.Up && !after.Up {
					down = append(down, id)
				}
				for _, a := range before.Addresses {
					if !slices.Contains(after.Addresses, a) {
						removed = append(removed, a)
					}
				}
			}
		}
		p.mu.Unlock()
		if err != nil {
			if ctx.Err() == nil && p.Fatal != nil {
				go p.Fatal(fmt.Errorf("Linux route reconciliation: %w", err))
			}
			return
		}
		for _, id := range down {
			if p.LineDown != nil {
				p.LineDown(id)
			}
		}
		for _, a := range removed {
			if p.AddressRemoved != nil {
				p.AddressRemoved(a)
			}
		}
	}
}
func (p *Platform) Cleanup(ctx context.Context) error {
	p.mu.Lock()
	cancel, done := p.monitorCancel, p.monitorDone
	p.monitorCancel = nil
	p.monitorDone = nil
	p.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	err := p.journal.Cleanup(ctx)
	if err == nil {
		p.owned = map[string]ownedObject{}
		p.lines = map[string]lineState{}
		p.capturing = false
		p.allocated = false
	}
	return err
}

func (p *Platform) binding(id string, v6 bool) (lineState, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	l, ok := p.lines[id]
	if !ok || !l.Up || (!v6 && !l.Default4) || (v6 && !l.Default6) {
		return l, fmt.Errorf("line %s has no usable default route", id)
	}
	return l, nil
}
