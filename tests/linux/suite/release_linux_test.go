//go:build linux

package suite

import (
	"testing"

	"github.com/AyoubAchour/net-switch/tests/linux/harness"
)

func TestOnlyApprovedStormAttributionGatesAreReleaseBlockers(t *testing.T) {
	want := map[string]bool{
		"overload.tcp-connection-storm":     false,
		"overload.tcp-handshakes-in-flight": false,
		"overload.tcp-flows-total":          false,
	}
	cases := Cases(Config{})
	for _, c := range cases {
		if c.ReleaseBlocker == "" {
			continue
		}
		if _, ok := want[c.ID]; !ok {
			t.Fatalf("unapproved release deferral: %s", c.ID)
		}
		want[c.ID] = true
	}
	for id, present := range want {
		if !present {
			t.Errorf("approved blocker missing from the release catalogue: %s", id)
		}
	}
	if harness.CheckRelease(cases) == nil {
		t.Fatal("unfinished eBPF attribution passed the release gate")
	}
}
