//go:build linux

package suite

import (
	"strings"
	"testing"

	"github.com/AyoubAchour/net-switch/tests/linux/harness"
)

func TestOnlyLoadAttributionGatesAreReleaseBlockers(t *testing.T) {
	want := map[string]bool{
		"overload.udp-sessions-per-app":      false,
		"overload.udp-sessions-total":        false,
		"overload.tcp-connection-storm":      false,
		"overload.tcp-handshakes-in-flight":  false,
		"overload.tcp-flows-total":           false,
		"overload.tcp-buffer-budget":         false,
		"overload.rejection-notices-per-app": false,
		"overload.rejection-notices-total":   false,
		"overload.timewait-cap":              false,
		"overload.udp-pending-bytes":         false,
		"overload.unknown-owner-limits":      false,
		"overload.tun-write-queue":           false,
		"overload.memory-at-limit":           false,
		"protocol.flows-pagination":          false,
	}
	cases := Cases(Config{})
	for _, c := range cases {
		if c.ReleaseBlocker == "" {
			continue
		}
		if _, ok := want[c.ID]; !ok {
			t.Fatalf("unexpected release deferral: %s", c.ID)
		}
		want[c.ID] = true
	}
	for id, present := range want {
		if !present {
			t.Errorf("load-attribution blocker missing from the release catalogue: %s", id)
		}
	}
	err := harness.CheckRelease(cases)
	if err == nil {
		t.Fatal("unfinished eBPF attribution passed the release gate")
	}
	for id := range want {
		if !strings.Contains(err.Error(), id+": release-blocker:") {
			t.Errorf("release command omitted %s: %v", id, err)
		}
	}
	for _, id := range []string{"lookup.gate-terminal", "lookup.gate-app-scope"} {
		if loadAttributionBlocker(id) != "" {
			t.Errorf("steady lookup gate was deferred: %s", id)
		}
	}
}
