package winengine

import (
	"net/netip"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
)

func TestRetiredLineStillObservesPhysicalLoss(t *testing.T) {
	table := flows.New(flows.Defaults(), nil)
	old := policy.Config{Lines: []platform.Line{{ID: "old", Interface: "old-interface"}}}
	if _, err := table.Apply(policy.Revision{N: 1, Config: old, Hash: policy.Hash(old)}); err != nil {
		t.Fatal(err)
	}
	x, err := table.Begin("tcp", platform.Tuple{Source: netip.MustParseAddrPort("192.0.2.1:12345"), Destination: netip.MustParseAddrPort("198.51.100.1:443")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = x.Resolve(platform.Owner{AppID: "app"}); err != nil {
		t.Fatal(err)
	}
	next := policy.Config{Lines: []platform.Line{{ID: "next", Interface: "new-interface"}}}
	if _, err := table.Apply(policy.Revision{N: 2, Config: next, Hash: policy.Hash(next)}); err != nil {
		t.Fatal(err)
	}
	if got := retainLineSelectors(next.Lines, old.Lines, table); len(got) != 2 || got[1].ID != "old" {
		t.Fatal("lost physical selector of held flow", got)
	}
	x.Close()
	if got := retainLineSelectors(next.Lines, old.Lines, table); len(got) != 1 {
		t.Fatal("unreferenced selector accumulated", got)
	}
}
