//go:build windows

package winengine

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"golang.org/x/sys/windows"
)

type recordedClosures struct {
	lines   []string
	sources []string
}

func (r *recordedClosures) CloseFlows(s flows.Selector, _ uint64) (flows.CloseResult, error) {
	if err := s.Validate(); err != nil {
		return flows.CloseResult{}, err
	}
	r.lines = append(r.lines, s.Line)
	return flows.CloseResult{}, nil
}

func (r *recordedClosures) CloseLineSource(line string, source netip.Addr) flows.CloseResult {
	r.sources = append(r.sources, line+" "+source.String())
	return flows.CloseResult{}
}

// RFC 4862 5.5.4: a deprecated address is still valid for existing
// connections; only preferred addresses take new ones.
func TestAddressUseByDADState(t *testing.T) {
	for _, c := range []struct {
		state               int32
		forNew, forExisting bool
	}{
		{windows.IpDadStatePreferred, true, true},
		{windows.IpDadStateDeprecated, false, true},
		{windows.IpDadStateTentative, false, false},
		{windows.IpDadStateDuplicate, false, false},
		{windows.IpDadStateInvalid, false, false},
	} {
		if forNew, forExisting := addressUse(c.state); forNew != c.forNew || forExisting != c.forExisting {
			t.Fatalf("state %d: new %t existing %t, want %t %t", c.state, forNew, forExisting, c.forNew, c.forExisting)
		}
	}
}

// SYSTEM-DESIGN 5.7, review of PR #46: an IPv6 address going from preferred to
// deprecated keeps its flows; only its removal closes them, and only on its
// own line, even when another line has the same address.
func TestLineEventsCloseOnlyLostAddressesOnTheirLine(t *testing.T) {
	v6 := netip.MustParseAddr("2001:db8:1::10")
	shared := netip.MustParseAddr("192.168.1.2")
	adapter := func(luid uint64, preferred, valid []netip.Addr) Adapter {
		return Adapter{LUID: luid, Up: true, Addresses: preferred, Valid: valid}
	}
	ethernet := func(preferred, valid []netip.Addr) Adapter { return adapter(1, preferred, valid) }
	wifi := adapter(2, []netip.Addr{shared}, []netip.Addr{shared})
	steps := []struct {
		name            string
		ethernet        Adapter
		lines, sources  []string
		newSourceForIP6 bool
	}{
		{"preferred", ethernet([]netip.Addr{shared, v6}, []netip.Addr{shared, v6}), nil, nil, true},
		{"deprecated", ethernet([]netip.Addr{shared}, []netip.Addr{shared, v6}), nil, nil, false},
		{"removed", ethernet([]netip.Addr{shared}, []netip.Addr{shared}), nil, []string{"eth " + v6.String()}, false},
		{"shared address lost on ethernet only", ethernet(nil, nil), nil, []string{"eth " + shared.String()}, false},
	}
	old := bindingTable{"eth": steps[0].ethernet, "wifi": wifi}
	for _, step := range steps[1:] {
		current := bindingTable{"eth": step.ethernet, "wifi": wifi}
		var got recordedClosures
		closeLost(&got, old, current)
		if !slices.Equal(got.lines, step.lines) || !slices.Equal(got.sources, step.sources) {
			t.Fatalf("%s: closed lines %v and sources %v, want %v and %v", step.name, got.lines, got.sources, step.lines, step.sources)
		}
		if slices.Contains(current["eth"].Addresses, v6) != step.newSourceForIP6 {
			t.Fatalf("%s: new IPv6 sockets may use the address: %t", step.name, !step.newSourceForIP6)
		}
		old = current
	}
	// A line that goes down, or moves to another interface, closes whole.
	for name, current := range map[string]bindingTable{
		"down":  {"eth": {LUID: 1, Valid: []netip.Addr{shared}}, "wifi": wifi},
		"moved": {"eth": adapter(3, []netip.Addr{shared}, []netip.Addr{shared}), "wifi": wifi},
		"gone":  {"wifi": wifi},
	} {
		var got recordedClosures
		closeLost(&got, bindingTable{"eth": ethernet([]netip.Addr{shared}, []netip.Addr{shared}), "wifi": wifi}, current)
		if !slices.Equal(got.lines, []string{"eth"}) || len(got.sources) != 0 {
			t.Fatalf("%s: closed lines %v and sources %v", name, got.lines, got.sources)
		}
	}
}
