package policy

import (
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"testing"
)

func TestZeroShareOnBlockedLine(t *testing.T) {
	c := config()
	c.Blocked = []string{"B"}
	c.Shares = map[string]uint64{"A": 0, "B": 0}
	p := compile(t, c)
	if d, err := p.Decide(platform.Owner{}, 5000, false, 1); err != nil || d.Line != "A" {
		t.Fatal("empty shares lost main fallback", d, err)
	}
	if _, err := p.Decide(platform.Owner{AppID: "pinned"}, 5000, false, 1); err != ErrBlocked {
		t.Fatal("blocked pin accepted", err)
	}
	c.Shares["B"] = 1
	if _, err := Compile(Revision{N: 1, Hash: Hash(c), Config: c}); err == nil {
		t.Fatal("positive blocked share accepted")
	}
}
