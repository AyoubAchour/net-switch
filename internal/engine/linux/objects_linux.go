//go:build linux

package linux

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/AyoubAchour/net-switch/internal/journal"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Every fingerprint is scoped to both this boot and this network namespace.
// Rule/route payloads contain the entire netlink object, not only its index.
type objects struct {
	boot, netns string
	tun         *Tun
}
type objectDriver struct {
	o    *objects
	kind string
}

func (d objectDriver) CleanupPriority() int {
	switch d.kind { case "rule": return 0; case "route": return 1; case "address": return 2; case "tun": return 3; default: return 4 }
}

func (o *objects) fingerprint(v any) journal.Fingerprint {
	b, _ := json.Marshal(v)
	return journal.Fingerprint{"boot": o.boot, "netns": o.netns, "object": string(b)}
}
func (d objectDriver) Validate(f journal.Fingerprint) error {
	if len(f) != 3 || f["boot"] == "" || f["netns"] == "" || !json.Valid([]byte(f["object"])) {
		return errors.New("invalid Linux ownership fingerprint")
	}
	return nil
}

func retryDump[T any](ctx context.Context, f func() (T, error)) (T, error) {
	var value T
	for i := 0; i < 8; i++ {
		if err := ctx.Err(); err != nil {
			return value, err
		}
		v, err := f()
		if !errors.Is(err, netlink.ErrDumpInterrupted) {
			return v, err
		}
	}
	return value, fmt.Errorf("netlink dump remained interrupted: %w", netlink.ErrDumpInterrupted)
}

func normalizedRoute(r netlink.Route) netlink.Route {
	// Link-state flags and IPv6 expiry are observations, not ownership.
	r.Flags &^= unix.RTNH_F_LINKDOWN | unix.RTNH_F_DEAD
	if r.Dst == nil {
		r.Dst = prefix(defaultCIDR(r.Family))
	}
	if len(r.Src) == 0 {
		r.Src = nil
	}
	if len(r.Gw) == 0 {
		r.Gw = nil
	}
	return r
}
func routeFP(o *objects, r netlink.Route) journal.Fingerprint {
	return o.fingerprint(normalizedRoute(r))
}
func ruleFP(o *objects, r netlink.Rule) journal.Fingerprint { return o.fingerprint(r) }

func (d objectDriver) Inspect(ctx context.Context, f journal.Fingerprint) (journal.Fingerprint, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if f["boot"] != d.o.boot || f["netns"] != d.o.netns {
		return nil, false, nil
	}
	switch d.kind {
	case "route":
		var want netlink.Route
		if err := json.Unmarshal([]byte(f["object"]), &want); err != nil {
			return nil, false, err
		}
		routes, err := retryDump(ctx, func() ([]netlink.Route, error) {
			return netlink.RouteListFiltered(want.Family, &netlink.Route{Table: want.Table}, netlink.RT_FILTER_TABLE)
		})
		if err != nil {
			return nil, false, err
		}
		for _, r := range routes {
			if maps.Equal(routeFP(d.o, r), f) {
				return f, true, nil
			}
		}
	case "rule":
		var want netlink.Rule
		if err := json.Unmarshal([]byte(f["object"]), &want); err != nil {
			return nil, false, err
		}
		rules, err := retryDump(ctx, func() ([]netlink.Rule, error) { return netlink.RuleList(want.Family) })
		if err != nil {
			return nil, false, err
		}
		for _, r := range rules {
			if maps.Equal(ruleFP(d.o, r), f) {
				return f, true, nil
			}
		}
	case "address":
		var want addressObject
		if err := json.Unmarshal([]byte(f["object"]), &want); err != nil {
			return nil, false, err
		}
		l, err := netlink.LinkByIndex(want.Index)
		if linkMissing(err) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		if l.Attrs().Alias != want.Alias || l.Attrs().Name != want.Name {
			return nil, false, nil
		}
		addrs, err := retryDump(ctx, func() ([]netlink.Addr, error) { return netlink.AddrList(l, netlink.FAMILY_ALL) })
		if err != nil {
			return nil, false, err
		}
		for _, a := range addrs {
			if a.IPNet.String() == want.CIDR {
				return f, true, nil
			}
		}
	case "tun":
		var want tunObject
		if err := json.Unmarshal([]byte(f["object"]), &want); err != nil {
			return nil, false, err
		}
		l, err := netlink.LinkByIndex(want.Index)
		if linkMissing(err) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		if l.Attrs().Name == want.Name && l.Attrs().Alias == want.Alias && l.Type() == "tuntap" {
			return f, true, nil
		}
	case "binding":
		// Socket bindings are ephemeral. Only the live process can own them;
		// closing its descriptor is their cleanup. No other process's fd is used.
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("unknown Linux object %q", d.kind)
	}
	return nil, false, nil
}

func linkMissing(err error) bool {
	var missing netlink.LinkNotFoundError
	return errors.As(err, &missing) || errors.Is(err, unix.ENODEV)
}

type addressObject struct {
	Index             int
	Name, Alias, CIDR string
}
type tunObject struct {
	Index       int
	Name, Alias string
	MTU         int
}

func (d objectDriver) Create(ctx context.Context, f journal.Fingerprint) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	switch d.kind {
	case "route":
		var v netlink.Route
		if err := json.Unmarshal([]byte(f["object"]), &v); err != nil {
			return err
		}
		return netlink.RouteAdd(&v)
	case "rule":
		var v netlink.Rule
		if err := json.Unmarshal([]byte(f["object"]), &v); err != nil {
			return err
		}
		return netlink.RuleAdd(&v)
	case "address":
		var v addressObject
		if err := json.Unmarshal([]byte(f["object"]), &v); err != nil {
			return err
		}
		l, err := netlink.LinkByIndex(v.Index)
		if err != nil {
			return err
		}
		if l.Attrs().Alias != v.Alias || l.Attrs().Name != v.Name {
			return errors.New("TUN identity changed")
		}
		return netlink.AddrAdd(l, &netlink.Addr{IPNet: prefix(v.CIDR), Flags: unix.IFA_F_NODAD})
	case "tun":
		var v tunObject
		if err := json.Unmarshal([]byte(f["object"]), &v); err != nil {
			return err
		}
		tun, err := openTun(v)
		if err == nil {
			d.o.tun = tun
		}
		return err
	case "binding":
		return nil
	}
	return errors.New("unknown object kind")
}
func (d objectDriver) Remove(ctx context.Context, f journal.Fingerprint) error {
	live, found, err := d.Inspect(ctx, f)
	if err != nil || !found || !maps.Equal(live, f) {
		return err
	}
	switch d.kind {
	case "route":
		var v netlink.Route
		json.Unmarshal([]byte(f["object"]), &v)
		err = netlink.RouteDel(&v)
	case "rule":
		var v netlink.Rule
		json.Unmarshal([]byte(f["object"]), &v)
		err = netlink.RuleDel(&v)
	case "address":
		var v addressObject
		json.Unmarshal([]byte(f["object"]), &v)
		l, e := netlink.LinkByIndex(v.Index)
		if e != nil {
			return e
		}
		err = netlink.AddrDel(l, &netlink.Addr{IPNet: prefix(v.CIDR)})
	case "tun":
		var v tunObject
		json.Unmarshal([]byte(f["object"]), &v)
		l, e := netlink.LinkByIndex(v.Index)
		if e != nil {
			return e
		}
		err = netlink.LinkDel(l)
	}
	if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EADDRNOTAVAIL) {
		return nil
	}
	return err
}
func prefix(s string) *net.IPNet {
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	n.IP = ip
	return n
}
func defaultCIDR(f int) string {
	if f == unix.AF_INET6 {
		return "::/0"
	}
	return "0.0.0.0/0"
}
func namespaceIdentity() (string, string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", "", err
	}
	var s unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &s); err != nil {
		return "", "", err
	}
	return strings.TrimSpace(string(b)), strconv.FormatUint(s.Ino, 10), nil
}
