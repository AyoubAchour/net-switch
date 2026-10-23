//go:build linux

// Package linux implements the engine's Linux boundary. It never shells out to
// ip, changes a firewall, or removes an object it cannot prove it owns.
package linux

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/journal"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const routeProtocol = 186

var netlinkTimeoutOnce sync.Once
var errAmbiguousLine = errors.New("address matches multiple interfaces")

var bypass = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"}

type lineState struct {
	ID, Name           string
	Interface          string
	MatchAddresses     []netip.Addr
	Index, N, Table    int
	Mark               uint32
	Addresses          []netip.Addr
	Up                 bool
	Default4, Default6 bool
	Unavailable        string
	lease              *lineLease
}
type Platform struct {
	testClose func()
	// Only lifecycle writers take routeMu. Dials and probes read bindings;
	// they never wait for netlink or a journal fsync.
	routeMu              sync.Mutex
	bindings             atomic.Pointer[bindingSnapshot]
	ctx                  context.Context
	Instance             string
	objects              *objects
	journal              *journal.Session
	base                 int
	allocated, capturing bool
	tunSpec              tunObject
	lines                map[string]lineState
	configured           map[string]bool
	lineUsed             func(string) bool
	slotsDirty           bool
	owned                map[string]ownedObject
	captureOwned         map[string]ownedObject
	captureOrder         []ownedObject
	observed             map[string]bool
	ipv4Only             bool
	journalDirty         bool
	monitorCancel        context.CancelFunc
	monitorDone          chan struct{}
	Owners               *Owners
	udpRoute             routeCounters
	// Callbacks run outside the platform lock.
	LineDown func(string)
	// AddressRemoved gets the line and the address it lost.
	AddressRemoved func(line string, addr netip.Addr)
	Fatal          func(error)
	WrapTun        func(platform.TunDevice) platform.TunDevice
	ProbeTLS       *tls.Config
	ProbeError     func() error
}
type bindingSnapshot struct {
	lines      map[string]lineState
	capturing  bool
	configured int
}

func (p *Platform) publishBindings() {
	view := &bindingSnapshot{lines: make(map[string]lineState, len(p.lines)), capturing: p.capturing, configured: len(p.configured)}
	for id, l := range p.lines {
		view.lines[id] = l
	}
	p.bindings.Store(view)
}

type ownedObject struct {
	kind string
	fp   journal.Fingerprint
}

func New(ctx context.Context, dir string) (*Platform, error) {
	return newPlatform(ctx, dir, nil)
}

func newPlatform(ctx context.Context, dir string, ownership journal.Locker) (*Platform, error) {
	// Route operations must not hold lifecycle cleanup indefinitely if netlink
	// stops answering. The lookup socket has its own tighter per-flow deadline.
	netlinkTimeoutOnce.Do(func() { _ = netlink.SetSocketTimeout(time.Second) })
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
	var owner unix.Stat_t
	if err := unix.Lstat(dir, &owner); err != nil {
		return nil, err
	}
	if owner.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("state directory belongs to another user")
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
	if ownership == nil {
		ownership = fileLock{filepath.Join(dir, "engine.lock")}
	}
	j := &journal.Journal{Store: diskStore{filepath.Join(dir, "engine-journal.json")}, Lock: ownership, Kinds: map[string]journal.Object{}}
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
	p.Owners.Close()
	if p.testClose != nil {
		p.testClose()
		p.testClose = nil
	}
	err := p.Cleanup(context.Background())
	return errors.Join(err, p.journal.Close())
}
func (p *Platform) OpenTun(ctx context.Context) (platform.TunDevice, error) {
	p.routeMu.Lock()
	defer p.routeMu.Unlock()
	if err := p.Owners.Warm(ctx); err != nil {
		return nil, err
	}
	rollback := func(cause error) (platform.TunDevice, error) {
		if p.objects.tun != nil {
			p.objects.tun.Close()
			p.objects.tun = nil
		}
		return nil, errors.Join(cause, p.journal.Cleanup(context.WithoutCancel(ctx)))
	}
	links, err := retryDump(ctx, netlink.LinkList)
	if err != nil {
		return nil, err
	}
	index := 1
	for _, l := range links {
		index = max(index, l.Attrs().Index+1)
	}
	p.tunSpec = tunObject{Index: index, Name: "ns" + p.Instance[:10], Alias: "netswitch:" + p.Instance, MTU: 9000, IngressQueue: 16384}
	if err := p.journal.Create(ctx, "tun", p.objects.fingerprint(p.tunSpec)); err != nil {
		return rollback(err)
	}
	p.ipv4Only = true
	for _, cidr := range []string{"198.18.0.1/30"} {
		v := addressObject{index, p.tunSpec.Name, p.tunSpec.Alias, cidr}
		if err := p.journal.Create(ctx, "address", p.objects.fingerprint(v)); err != nil {
			return rollback(err)
		}
	}
	p.objects.tun.beforeContextClose = p.Quiesce
	if p.WrapTun != nil {
		return p.WrapTun(p.objects.tun), nil
	}
	return p.objects.tun, nil
}

// The default applies to newly created links, not to existing physical lines.
// Change only our journal-owned TUN; a physical IPv6 line requires capture even
// when the TUN inherited disable_ipv6=1.
func (p *Platform) enableIPv6(ctx context.Context) error {
	link, err := netlink.LinkByIndex(p.tunSpec.Index)
	if err != nil {
		return err
	}
	if p.objects.tun == nil || link.Attrs().Name != p.tunSpec.Name || link.Attrs().Alias != p.tunSpec.Alias {
		return errors.New("engine TUN ownership changed before IPv6 configuration")
	}
	path := "/proc/sys/net/ipv6/conf/" + p.tunSpec.Name + "/disable_ipv6"
	value, err := readKernelFile(path, 16)
	if err != nil {
		return fmt.Errorf("read IPv6 state on engine TUN: %w", err)
	}
	before := strings.TrimSpace(string(value))
	if before != "0" && before != "1" {
		return fmt.Errorf("invalid engine TUN disable_ipv6 value %q", before)
	}
	if before == "1" {
		if err := os.WriteFile(path, []byte("0\n"), 0600); err != nil {
			return fmt.Errorf("enable IPv6 on owned engine TUN %s (inherited disable_ipv6=1): %w", p.tunSpec.Name, err)
		}
	}
	log.Printf("engine TUN IPv6 instance=%s name=%s disable_ipv6_before=%s after=0 wrote=%t", p.Instance, p.tunSpec.Name, before, before == "1")
	v := addressObject{p.tunSpec.Index, p.tunSpec.Name, p.tunSpec.Alias, "fdfe:dcba:9876::1/126"}
	if err := p.journal.Create(ctx, "address", p.objects.fingerprint(v)); err != nil {
		return err
	}
	p.ipv4Only = false
	return nil
}

func resolveLine(ctx context.Context, links []netlink.Link, name string, addresses []netip.Addr) (netlink.Link, error) {
	var match netlink.Link
	for _, link := range links {
		if name != "" {
			if link.Attrs().Name == name {
				return link, nil
			}
			continue
		}
		addrs, err := retryDump(ctx, func() ([]netlink.Addr, error) { return netlink.AddrList(link, netlink.FAMILY_ALL) })
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			ip, _ := netip.AddrFromSlice(a.IP)
			if slices.Contains(addresses, ip.Unmap()) {
				if match != nil && match.Attrs().Index != link.Attrs().Index {
					return nil, errAmbiguousLine
				}
				match = link
			}
		}
	}
	return match, nil
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
		for _, r := range rules {
			all = append(all, r.rule)
		}
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
	p.routeMu.Lock()
	before := make(map[string]lineState, len(p.lines))
	for id, line := range p.lines {
		before[id] = line
	}
	var down []string
	var removed []lineAddress
	defer func() {
		p.routeMu.Unlock()
		for _, id := range down {
			if p.LineDown != nil {
				p.LineDown(id)
			}
		}
		for _, address := range removed {
			if p.AddressRemoved != nil {
				p.AddressRemoved(address.Line, address.Address)
			}
		}
	}()
	if len(lines) == 0 || len(lines) > 255 {
		return errors.New("Linux routing needs 1–255 lines")
	}
	if !p.allocated {
		if err := p.allocate(ctx, len(lines)); err != nil {
			return err
		}
	}
	wanted := make(map[string]bool, len(lines))
	for _, line := range lines {
		wanted[line.ID] = true
	}
	// Only previously retired/unreferenced lines can be reclaimed before the
	// new policy commits. Remove their selecting rules/routes before slot reuse.
	p.retireLines(wanted)
	if p.slotsDirty {
		if err := p.reconcileRetry(ctx); err != nil {
			return err
		}
		p.slotsDirty = false
	}
	// Resolve requested lines before publishing bindings. Old IDs retain their table
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
		previous, existing := next[line.ID]
		match, err := resolveLine(ctx, links, line.Interface, line.Addresses)
		ambiguous := errors.Is(err, errAmbiguousLine)
		if err != nil && !ambiguous {
			return err
		}
		if match != nil && match.Attrs().Index == p.tunSpec.Index {
			return errors.New("the TUN cannot be an egress line")
		}
		if existing {
			if match != nil {
				previous.Index, previous.Name = match.Attrs().Index, match.Attrs().Name
			}
			previous.Interface, previous.MatchAddresses = line.Interface, slices.Clone(line.Addresses)
			next[line.ID] = previous
			continue
		}
		n := freeLineSlot(next)
		if n == 0 {
			return errors.New("all line slots are still configured or held by live sockets")
		}
		var name string
		var index int
		if match != nil {
			name, index = match.Attrs().Name, match.Attrs().Index
		}
		next[line.ID] = lineState{ID: line.ID, Name: name, Interface: line.Interface, MatchAddresses: slices.Clone(line.Addresses), Index: index, N: n, Table: 21000 + p.base + n, Mark: uint32(0x4e530000 + p.base + n), lease: &lineLease{}}
	}
	old, oldConfigured := p.lines, p.configured
	p.lines = next
	p.configured = wanted
	if err := p.reconcileRetry(ctx); err != nil {
		p.lines = old
		p.configured = oldConfigured
		if p.capturing && p.Fatal != nil {
			go p.Fatal(fmt.Errorf("cannot reconcile line revision safely: %w", err))
		}
		return err
	}
	down, removed = lineChanges(before, p.lines)
	return nil
}

func (p *Platform) add(ctx context.Context, kind string, fp journal.Fingerprint) error {
	key := kind + fp["object"]
	if _, ok := p.owned[key]; ok {
		if kind == "binding" || p.observed[key] {
			return nil
		}
		p.journalDirty = true
		// Network managers can remove our objects. Retire the absent record,
		// then journal a fresh intent before restoring it. A colliding foreign
		// object makes Create fail; it is never replaced or claimed.
		if err := p.journal.Remove(ctx, kind, fp); err != nil {
			return err
		}
		if err := p.journal.Create(ctx, kind, fp); err != nil {
			return err
		}
		p.observed[key] = true
		return nil
	}
	p.journalDirty = true
	if kind == "route" {
		var next netlink.Route
		if err := json.Unmarshal([]byte(fp["object"]), &next); err != nil {
			return err
		}
		for previousKey, object := range p.owned {
			if object.kind != "route" {
				continue
			}
			var old netlink.Route
			if err := json.Unmarshal([]byte(object.fp["object"]), &old); err != nil {
				return err
			}
			if old.Family == next.Family && old.Table == next.Table && old.Priority == next.Priority && old.Tos == next.Tos && old.Dst.String() == next.Dst.String() {
				if old.Type == unix.RTN_UNREACHABLE && next.Type != old.Type {
					return errors.New("physical route collides with the reserved unreachable fallback")
				}
				if p.observed[previousKey] {
					if err := p.journal.Replace(ctx, kind, object.fp, fp); err != nil {
						return err
					}
				} else {
					if err := p.journal.Remove(ctx, kind, object.fp); err != nil {
						return err
					}
					if err := p.journal.Create(ctx, kind, fp); err != nil {
						return err
					}
				}
				delete(p.owned, previousKey)
				p.owned[key] = ownedObject{kind, fp}
				return nil
			}
		}
	}
	if err := p.journal.Create(ctx, kind, fp); err != nil {
		return err
	}
	p.owned[key] = ownedObject{kind, fp}
	return nil
}
func (p *Platform) reconcileLocked(ctx context.Context) error {
	links, err := retryDump(ctx, netlink.LinkList)
	if err != nil {
		return err
	}
	resolved := make(map[string]netlink.Link, len(p.lines))
	unavailable := make(map[string]string)
	for id, line := range p.lines {
		name := line.Interface
		if name == "" && len(line.MatchAddresses) == 0 {
			name = line.Name
		}
		link, err := resolveLine(ctx, links, name, line.MatchAddresses)
		if errors.Is(err, errAmbiguousLine) {
			unavailable[id] = err.Error()
			if line.Unavailable != err.Error() {
				log.Printf("Linux line %s unavailable: %v", id, err)
			}
			continue
		}
		if err != nil {
			return err
		}
		resolved[id] = link
		if link != nil && p.ipv4Only {
			addrs, err := retryDump(ctx, func() ([]netlink.Addr, error) { return netlink.AddrList(link, unix.AF_INET6) })
			if err != nil {
				return err
			}
			hasIPv6 := false
			for _, a := range addrs {
				hasIPv6 = hasIPv6 || !a.IP.IsLoopback()
			}
			if hasIPv6 {
				if err := p.enableIPv6(ctx); err != nil {
					return err
				}
			}
		}
	}
	routes, err := allRoutes(ctx)
	if err != nil {
		return err
	}
	p.observed = make(map[string]bool, len(routes)+len(p.owned))
	var foreignRoutes []netlink.Route
	var foreignRules []netlink.Rule
	for _, r := range routes {
		key := "route" + routeFP(p.objects, r)["object"]
		p.observed[key] = true
		if _, owned := p.owned[key]; !owned {
			foreignRoutes = append(foreignRoutes, r)
		}
	}
	for _, family := range p.families() {
		rules, err := readRules(ctx, family)
		if err != nil {
			return err
		}
		for _, r := range rules {
			key := "rule" + ruleFP(p.objects, r.rule)["object"]
			_, owned := p.owned[key]
			if len(r.extra) == 0 {
				p.observed[key] = true
			}
			if !owned || len(r.extra) != 0 {
				foreignRules = append(foreignRules, r.rule)
			}
		}
	}
	for _, rule := range foreignRules {
		if !layoutAvailable(p.base, 255, []netlink.Rule{rule}, nil) {
			return fmt.Errorf("foreign rule now conflicts with the engine layout; restoring normal routing: %s", ruleFP(p.objects, rule)["object"])
		}
	}
	for _, route := range foreignRoutes {
		if !layoutAvailable(p.base, 255, nil, []netlink.Route{route}) {
			return fmt.Errorf("foreign route now conflicts with the engine layout; restoring normal routing: %s", routeFP(p.objects, route)["object"])
		}
	}
	desired := map[string]ownedObject{}
	keep := func(kind string, fp journal.Fingerprint) error {
		desired[kind+fp["object"]] = ownedObject{kind, fp}
		return p.add(ctx, kind, fp)
	}
	// Fallback routes exist before every selector and never leave the table
	// during reconciliation, including when a DHCP default disappears.
	for _, l := range p.lines {
		for _, fam := range p.families() {
			r := netlink.Route{Family: fam, Table: l.Table, Dst: prefix(defaultCIDR(fam)), Type: unix.RTN_UNREACHABLE, Protocol: routeProtocol, Priority: int(^uint32(0))}
			// Linux associates IPv6 reject routes with loopback. Record that
			// index before creating it, so the live fingerprint matches cleanup.
			if fam == unix.AF_INET6 {
				lo, err := netlink.LinkByName("lo")
				if err != nil {
					return err
				}
				r.LinkIndex = lo.Attrs().Index
			}
			if err := keep("route", routeFP(p.objects, r)); err != nil {
				return err
			}
		}
	}
	for id, l := range p.lines {
		// Resolve the original selector, including an address-only line whose
		// replacement adapter has a different name and index.
		link := resolved[id]
		l.Up = false
		l.Default4 = false
		l.Default6 = false
		l.Addresses = nil
		l.Unavailable = unavailable[id]
		if link != nil {
			l.Index = link.Attrs().Index
			l.Name = link.Attrs().Name
			l.Up = link.Attrs().Flags&net.FlagUp != 0
			addrs, err := retryDump(ctx, func() ([]netlink.Addr, error) { return netlink.AddrList(link, netlink.FAMILY_ALL) })
			if err != nil {
				return err
			}
			for _, a := range addrs {
				ip, ok := netip.AddrFromSlice(a.IP)
				if ok && usableAddress(a.Flags, ip, p.ipv4Only) {
					l.Addresses = append(l.Addresses, ip.Unmap())
				}
			}
		}
		for _, r := range routes {
			if !l.Up || (p.ipv4Only && r.Family == unix.AF_INET6) || r.LinkIndex != l.Index || r.Type != unix.RTN_UNICAST || r.Table == unix.RT_TABLE_LOCAL || (r.Table >= 21000+p.base && r.Table <= 21255+p.base) || r.Flags&unix.RTM_F_CLONED != 0 {
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
		for _, fam := range p.families() {
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
	// Preserve ordinary link/default-route recovery on every unambiguous
	// line. A DHCP gap must not become a whole-engine shutdown merely because
	// a different line is ambiguous. Fail open when ambiguity itself leaves
	// no line that can safely be selected.
	if len(unavailable) > 0 && len(unavailable) == len(p.lines) {
		return fmt.Errorf("no unambiguous line remains: %v", unavailable)
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
			if _, ok := p.captureOwned[key]; ok {
				continue
			}
			if err := p.journal.Remove(ctx, kind, object.fp); err != nil {
				return err
			}
			p.journalDirty = true
			delete(p.owned, key)
		}
	}
	// Restore bypass and capture only after physical tables are complete.
	for _, kind := range []string{"route", "rule"} {
		for _, object := range p.captureOrder {
			if object.kind == kind {
				if err := p.add(ctx, kind, object.fp); err != nil {
					return err
				}
			}
		}
	}
	if !p.ipv4Only && p.capturing {
		if err := p.captureFamily(ctx, unix.AF_INET6); err != nil {
			return err
		}
	}
	if p.journalDirty {
		if err := p.journal.Compact(); err != nil {
			return err
		}
		p.journalDirty = false
	}
	p.publishBindings()
	return nil
}

func (p *Platform) families() []int {
	if p.ipv4Only {
		return []int{unix.AF_INET}
	}
	return []int{unix.AF_INET, unix.AF_INET6}
}

func (p *Platform) Capture(ctx context.Context) error {
	p.routeMu.Lock()
	defer p.routeMu.Unlock()
	if p.capturing {
		return nil
	}
	p.captureOwned = make(map[string]ownedObject)
	p.captureOrder = nil
	for _, fam := range p.families() {
		if err := p.captureFamily(ctx, fam); err != nil {
			return err
		}
	}
	p.capturing = true
	p.publishBindings()
	run, cancel := context.WithCancel(p.ctx)
	p.monitorCancel = cancel
	p.monitorDone = make(chan struct{})
	go p.monitor(run, p.monitorDone)
	return nil
}

func (p *Platform) captureFamily(ctx context.Context, family int) error {
	create := func(kind string, fp journal.Fingerprint) error {
		if err := p.add(ctx, kind, fp); err != nil {
			return err
		}
		key := kind + fp["object"]
		if _, exists := p.captureOwned[key]; !exists {
			p.captureOwned[key] = ownedObject{kind, fp}
			p.captureOrder = append(p.captureOrder, ownedObject{kind, fp})
		}
		return nil
	}
	for _, cidr := range bypass {
		r := netlink.NewRule()
		r.Family = unix.AF_INET
		if prefix(cidr).IP.To4() == nil {
			r.Family = unix.AF_INET6
		}
		if r.Family != family {
			continue
		}
		r.Priority = p.base + 9100
		r.Table = unix.RT_TABLE_MAIN
		r.Dst = prefix(cidr)
		r.Protocol = routeProtocol
		r.Type = 1
		if err := create("rule", ruleFP(p.objects, *r)); err != nil {
			return err
		}
	}
	for _, fam := range []int{family} {
		r := netlink.Route{Family: fam, Table: 21000 + p.base, LinkIndex: p.tunSpec.Index, Dst: prefix(defaultCIDR(fam)), Type: unix.RTN_UNICAST, Protocol: routeProtocol, Scope: netlink.SCOPE_LINK}
		// IPv6 substitutes IP6_RT_PRIO_USER (1024) for an omitted/zero
		// metric. Persist the value that will actually identify this route.
		if fam == unix.AF_INET6 {
			r.Priority = 1024
			// rt6_fill_node always reports RT_SCOPE_UNIVERSE. IPv6's
			// on-link selection is represented by the missing gateway.
			r.Scope = netlink.SCOPE_UNIVERSE
		}
		if err := create("route", routeFP(p.objects, r)); err != nil {
			return err
		}
	}
	for _, fam := range []int{family} {
		r := netlink.NewRule()
		r.Family = fam
		r.Priority = p.base + 12000
		r.Table = 21000 + p.base
		r.IifName = "lo"
		r.Protocol = routeProtocol
		r.Type = 1
		if err := create("rule", ruleFP(p.objects, *r)); err != nil {
			return err
		}
	}
	return nil
}

func transientNetlink(err error) bool {
	var timeout net.Error
	return errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) ||
		errors.Is(err, unix.ENOBUFS) || errors.Is(err, unix.ETIMEDOUT) ||
		errors.Is(err, netlink.ErrDumpInterrupted) || (errors.As(err, &timeout) && timeout.Timeout())
}

func (p *Platform) reconcileRetry(ctx context.Context) error {
	return retryReconcile(ctx, p.reconcileLocked)
}

func retryReconcile(ctx context.Context, reconcile func(context.Context) error) error {
	for attempt := 0; ; attempt++ {
		err := reconcile(ctx)
		if err == nil || !transientNetlink(err) || attempt == 2 || ctx.Err() != nil {
			return err
		}
		log.Printf("Linux route reconciliation failed temporarily (attempt %d/3): %v; retrying", attempt+1, err)
		timer := time.NewTimer(time.Duration(attempt+1) * 100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
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
		p.routeMu.Lock()
		old := make(map[string]lineState, len(p.lines))
		for id, l := range p.lines {
			old[id] = l
		}
		p.retireLines(p.configured)
		err := p.reconcileRetry(ctx)
		var down []string
		var removed []lineAddress
		if err == nil {
			p.slotsDirty = false
			down, removed = lineChanges(old, p.lines)
		}
		if err != nil {
			p.bindings.Store(nil)
		}
		p.routeMu.Unlock()
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
				p.AddressRemoved(a.Line, a.Address)
			}
		}
	}
}

// lineAddress is one local address of one line.
type lineAddress struct {
	Line    string
	Address netip.Addr
}

// lineChanges compares two reconciled line states: the lines that went down
// or moved to another interface, and each address a line no longer has, with
// the line that lost it. Two routers commonly hand out the same 192.168.1.x,
// so an address alone does not name a line (SYSTEM-DESIGN 5.7).
func lineChanges(old, current map[string]lineState) (down []string, removed []lineAddress) {
	for id, before := range old {
		after := current[id]
		if before.Up && (!after.Up || before.Index != after.Index) {
			down = append(down, id)
		}
		for _, a := range before.Addresses {
			if !slices.Contains(after.Addresses, a) {
				removed = append(removed, lineAddress{id, a})
			}
		}
	}
	return down, removed
}

// usableAddress says whether a netlink address belongs in a line's addresses.
// A tentative IPv6 address (duplicate detection still running) does not. A
// deprecated one (IFA_F_DEPRECATED: its preferred lifetime ended, its valid
// lifetime not) stays: existing flows keep using it (RFC 4862 5.5.4), and
// the kernel already avoids it for new sources (RFC 6724 rule 3), so it is
// never reported removed until it is actually gone.
func usableAddress(flags int, ip netip.Addr, ipv4Only bool) bool {
	return flags&unix.IFA_F_TENTATIVE == 0 && (!ipv4Only || ip.Is4() || ip.Is4In6())
}
func (p *Platform) Quiesce() {
	p.routeMu.Lock()
	cancel, done := p.monitorCancel, p.monitorDone
	p.routeMu.Unlock()
	if cancel != nil {
		cancel()
	}
	// Retain the same completion channel until cleanup. Simultaneous TUN
	// cancellation and Engine.Stop must both join, not let the second caller
	// close the device while the first caller is still waiting for repair.
	if done != nil {
		<-done
	}
}

func (p *Platform) Cleanup(ctx context.Context) error {
	p.bindings.Store(nil)
	p.Quiesce()
	p.routeMu.Lock()
	defer p.routeMu.Unlock()
	p.monitorCancel = nil
	p.monitorDone = nil
	p.bindings.Store(nil)
	err := p.journal.Cleanup(ctx)
	if err == nil {
		p.owned = map[string]ownedObject{}
		p.captureOwned = nil
		p.captureOrder = nil
		p.lines = map[string]lineState{}
		p.configured = nil
		p.slotsDirty = false
		p.capturing = false
		p.allocated = false
	}
	return err
}

func (p *Platform) binding(id string, v6 bool) (lineState, error) {
	view := p.bindings.Load()
	if view == nil {
		return lineState{}, errors.New("line bindings are unavailable")
	}
	l, ok := view.lines[id]
	if ok && l.Unavailable != "" {
		return l, fmt.Errorf("line %s unavailable: %s", id, l.Unavailable)
	}
	if !ok || !l.Up || (!v6 && !l.Default4) || (v6 && !l.Default6) {
		return l, fmt.Errorf("line %s has no usable default route", id)
	}
	return l, nil
}
