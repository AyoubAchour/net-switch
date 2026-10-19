//go:build linux

package nsengine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

// lineAddresses reads an interface's global addresses in a namespace, the
// addresses a revision gives the line.
func lineAddresses(ctx context.Context, netns, iface string) ([]netip.Addr, error) {
	out, err := exec.CommandContext(ctx, "ip", "-n", netns, "-j", "addr", "show", "dev", iface).Output()
	if err != nil {
		return nil, fmt.Errorf("ip -n %s addr show dev %s: %w", netns, iface, err)
	}
	var links []struct {
		AddrInfo []struct {
			Local string `json:"local"`
			Scope string `json:"scope"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(out, &links); err != nil {
		return nil, fmt.Errorf("ip -j addr: %w: %s", err, strings.TrimSpace(string(out)))
	}
	var addrs []netip.Addr
	for _, link := range links {
		for _, info := range link.AddrInfo {
			if info.Scope != "global" {
				continue
			}
			addr, err := netip.ParseAddr(info.Local)
			if err != nil {
				return nil, fmt.Errorf("ip -j addr: %w", err)
			}
			addrs = append(addrs, addr)
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%s has no global address in %s", iface, netns)
	}
	return addrs, nil
}
