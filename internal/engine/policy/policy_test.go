package policy

import (
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

func config() Config {
	return Config{Lines: []platform.Line{{ID: "A"}, {ID: "B"}}, AppLines: map[string]string{"pinned": "B"}, Lanes: map[string]string{"A": "A", "B": "B"}, Shares: map[string]uint64{"A": 2, "B": 1}, Combine: true}
}
func compile(t *testing.T, c Config) *Policy {
	t.Helper()
	p, err := Compile(Revision{N: 1, Hash: Hash(c), Config: c})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestDecisionTable(t *testing.T) {
	for _, tc := range []struct {
		name, app, line         string
		port                    uint16
		v6, blocked, empty, off bool
		target                  string
		reject                  bool
	}{
		{name: "pin", app: "pinned", port: 5000, line: "B"},
		{name: "pin survives low port", app: "pinned", port: 80, line: "B"},
		{name: "unknown low port", port: 80, line: "A"},
		{name: "combining off", port: 5000, off: true, line: "A"},
		{name: "blocked pin", app: "pinned", port: 5000, blocked: true, reject: true},
		{name: "IPv6 reject", port: 5000, v6: true, reject: true},
		{name: "empty shares main exception", port: 5000, empty: true, target: "B", line: "B"},
		{name: "pin follows lane", app: "pinned", port: 5000, target: "A", line: "A"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := config()
			if tc.blocked {
				c.Blocked = []string{"B"}
				delete(c.Shares, "B")
			}
			if tc.empty {
				c.Shares = nil
				c.Lanes["A"] = tc.target
			} else if tc.target != "" {
				c.Lanes["B"] = tc.target
			}
			if tc.off {
				c.Combine = false
			}
			p := compile(t, c)
			d, err := p.Decide(platform.Owner{AppID: tc.app}, tc.port, tc.v6, 1)
			if (err != nil) != tc.reject || (!tc.reject && d.Line != tc.line) {
				t.Fatalf("decision %+v, %v", d, err)
			}
		})
	}
}
func TestEvenness(t *testing.T) {
	p := compile(t, config())
	for _, n := range []int{10, 50, 300} {
		counts := map[string]int{}
		for k := 1; k <= n; k++ {
			d, err := p.Decide(platform.Owner{}, 5000, false, uint64(k))
			if err != nil {
				t.Fatal(err)
			}
			counts[d.Line]++
		}
		delta := float64(counts["A"]) - float64(n)*2/3
		if delta < -2 || delta > 2 {
			t.Fatalf("%d flows: %v", n, counts)
		}
	}
}
func TestImmutableAndPrediction(t *testing.T) {
	c := config()
	p := compile(t, c)
	c.Lanes["B"] = "A"
	if p.Predict("pinned").Line != "B" {
		t.Fatal("published config mutated")
	}
	d := p.Predict("unknown").Distribution
	if d["A"] != 2.0/3 || d["B"] != 1.0/3 {
		t.Fatal(d)
	}
}
func TestShareOverflow(t *testing.T) {
	c := config()
	c.Shares = map[string]uint64{"A": ^uint64(0), "B": 1}
	if _, err := Compile(Revision{N: 1, Hash: Hash(c), Config: c}); err == nil {
		t.Fatal("overflow accepted")
	}
}
