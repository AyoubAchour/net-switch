//go:build linux

package topo

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/AyoubAchour/net-switch/tests/linux/engine"
)

// AddDefault gives the PC a default route over the line (IPv4 and IPv6), with
// the line's metric, as NetworkManager does for each connection.
func (n *Net) AddDefault(ctx context.Context, id engine.LineID) error {
	l := Line(id)
	metric := strconv.Itoa(l.Metric)
	// The gateway's address picks the family; batch lines can't take -6.
	return n.R.Batch(ctx, DUT, []string{
		"route replace default via " + l.GW4.String() + " dev " + l.Iface + " metric " + metric,
		"route replace default via " + l.GW6.String() + " dev " + l.Iface + " metric " + metric,
	})
}

// DelDefault removes the line's default routes, as when its DHCP lease ends.
func (n *Net) DelDefault(ctx context.Context, id engine.LineID) error {
	l := Line(id)
	if _, err := n.R.IP(ctx, DUT, "-4", "route", "del", "default", "dev", l.Iface); err != nil {
		return err
	}
	_, err := n.R.IP(ctx, DUT, "-6", "route", "del", "default", "dev", l.Iface)
	return err
}

// LinkDown takes the PC's interface for the line down (a cable pulled).
func (n *Net) LinkDown(ctx context.Context, id engine.LineID) error {
	_, err := n.R.IP(ctx, DUT, "link", "set", Line(id).Iface, "down")
	return err
}

// LinkUp brings it back with its default routes, as NetworkManager would.
func (n *Net) LinkUp(ctx context.Context, id engine.LineID) error {
	if _, err := n.R.IP(ctx, DUT, "link", "set", Line(id).Iface, "up"); err != nil {
		return err
	}
	return n.AddDefault(ctx, id)
}

// UplinkDown cuts the line's router off from the internet: the line stays up
// on the PC but reaches nothing.
func (n *Net) UplinkDown(ctx context.Context, id engine.LineID) error {
	_, err := n.R.IP(ctx, Line(id).ISP, "link", "set", "wan", "down")
	return err
}

// UplinkUp reconnects the router.
func (n *Net) UplinkUp(ctx context.Context, id engine.LineID) error {
	l := Line(id)
	return n.R.Batch(ctx, l.ISP, []string{
		"link set wan up",
		"route replace default via " + l.Core4.Addr().String(),
		"route replace default via " + l.Core6.Addr().String(),
	})
}

// SetNetem degrades the line between the PC and its router, both ways, with a
// tc netem spec such as "delay 10ms 5ms loss 5% reorder 25% 50%".
func (n *Net) SetNetem(ctx context.Context, id engine.LineID, spec []string) error {
	l := Line(id)
	for _, side := range []struct{ ns, dev string }{{DUT, l.Iface}, {l.ISP, "lan"}} {
		args := append([]string{"qdisc", "replace", "dev", side.dev, "root", "netem"}, spec...)
		if _, err := n.R.In(ctx, side.ns, "tc", args...); err != nil {
			return err
		}
	}
	return nil
}

// ClearNetem removes SetNetem's degradation.
func (n *Net) ClearNetem(ctx context.Context, id engine.LineID) error {
	l := Line(id)
	for _, side := range []struct{ ns, dev string }{{DUT, l.Iface}, {l.ISP, "lan"}} {
		if _, err := n.R.In(ctx, side.ns, "tc", "qdisc", "del", "dev", side.dev, "root"); err != nil {
			return err
		}
	}
	return nil
}

// SetPathMTU makes the line's router forward at most mtu bytes per packet,
// both ways, IPv4 and IPv6. Every link stays at 1500, so neither the PC nor
// the servers see the limit on their own interfaces: TCP can't avoid it with
// its MSS, and both ends must discover it from the router's ICMP
// "fragmentation needed" / "packet too big", as across a real smaller hop.
// (The kernel's pmtu.sh selftest keeps the small MTU on a router for the same
// reason. IPv6 forwarding honours a route's MTU only when it's locked.)
func (n *Net) SetPathMTU(ctx context.Context, id engine.LineID, mtu int) error {
	l := Line(id)
	lock := "mtu lock " + strconv.Itoa(mtu)
	return n.R.Batch(ctx, l.ISP, []string{
		"route replace default via " + l.Core4.Addr().String() + " " + lock,
		"route replace default via " + l.Core6.Addr().String() + " " + lock,
		"route replace " + l.Addr4.Masked().String() + " dev lan proto kernel scope link src " + l.GW4.String() + " " + lock,
		"route replace " + l.Addr6.Masked().String() + " dev lan proto kernel metric 256 " + lock,
	})
}

// PathMTU reads back the MTUs the line's router forwards with (route -> mtu).
func (n *Net) PathMTU(ctx context.Context, id engine.LineID) (map[string]string, error) {
	l := Line(id)
	out := map[string]string{}
	for _, family := range []string{"-4", "-6"} {
		text, err := n.R.IP(ctx, l.ISP, family, "route", "show")
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(text, "\n") {
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "mtu" && i+1 < len(fields) {
					v := fields[i+1]
					if v == "lock" && i+2 < len(fields) {
						v = fields[i+2]
					}
					out[fields[0]+" "+family] = v
				}
			}
		}
	}
	return out, nil
}

// ChangeAddress moves the PC's IPv4 address on a line to another in the same
// subnet (a new DHCP lease), adding the new one before removing the old, and
// keeps the default route, as NetworkManager does.
func (n *Net) ChangeAddress(ctx context.Context, id engine.LineID, to netip.Prefix) error {
	l := Line(id)
	if err := n.R.Batch(ctx, DUT, []string{
		"addr add " + to.String() + " dev " + l.Iface,
		"addr del " + l.Addr4.String() + " dev " + l.Iface,
	}); err != nil {
		return err
	}
	return n.AddDefault(ctx, id)
}

// SetRPFilter sets reverse-path filtering for the PC: 0 off, 1 strict, 2 loose.
func (n *Net) SetRPFilter(ctx context.Context, mode int) error {
	value := strconv.Itoa(mode)
	settings := []string{"net.ipv4.conf.all.rp_filter=" + value, "net.ipv4.conf.default.rp_filter=" + value, "net.ipv4.conf.lo.rp_filter=" + value}
	for _, l := range Lines {
		settings = append(settings, "net.ipv4.conf."+l.Iface+".rp_filter="+value)
	}
	return n.R.Sysctl(ctx, DUT, settings...)
}

// Container is a container network on the PC, as Docker sets one up.
const (
	ContainerBridge = "docker0"
	ContainerAddr   = "172.17.0.2"
)

// AddContainer creates a container namespace behind a docker0 bridge on the
// PC, with forwarding and masquerading.
func (n *Net) AddContainer(ctx context.Context) error {
	r := n.R
	if _, err := r.Run(ctx, "ip", "netns", "add", CTR); err != nil {
		return err
	}
	if _, err := r.Run(ctx, "ip", "link", "add", "eth0", "netns", CTR, "type", "veth", "peer", "name", "veth-ctr", "netns", DUT); err != nil {
		return err
	}
	if err := r.Batch(ctx, DUT, []string{
		"link add " + ContainerBridge + " type bridge",
		"addr add 172.17.0.1/16 dev " + ContainerBridge,
		"link set " + ContainerBridge + " up",
		"link set veth-ctr master " + ContainerBridge,
		"link set veth-ctr up",
	}); err != nil {
		return err
	}
	if err := r.Batch(ctx, CTR, []string{
		"link set lo up",
		"addr add " + ContainerAddr + "/16 dev eth0",
		"link set eth0 up",
		"route add default via 172.17.0.1",
	}); err != nil {
		return err
	}
	if err := r.Sysctl(ctx, DUT, "net.ipv4.ip_forward=1"); err != nil {
		return err
	}
	return r.Nft(ctx, DUT, fmt.Sprintf("table ip containernat {\n chain post {\n  type nat hook postrouting priority 100; policy accept;\n  ip saddr 172.17.0.0/16 oifname != %q masquerade\n }\n}\n", ContainerBridge))
}
