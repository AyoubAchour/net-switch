package flows

import (
	"net/netip"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
)

func TestLineReferencesCoverPendingDialsButNotRetiredAccounting(t *testing.T) {
	f := table(t, Defaults())
	x := admit(t, f, "tcp", "app")
	line := x.(*ticket).record.Line
	c := policy.Config{Lines: []platform.Line{{ID: "replacement"}}}
	if _, err := f.Apply(policy.Revision{N: 2, Config: c, Hash: policy.Hash(c)}); err != nil {
		t.Fatal(err)
	}
	if !f.ReferencesLine(line) || !f.ReferencesLine("replacement") {
		t.Fatal("pending dial or configured line lost its reference")
	}
	x.Retire()
	if f.ReferencesLine(line) {
		t.Fatal("retired accounting retained routing slot")
	}
	x.Add(7, 11)
	x.Close()
	x.Close()
	if f.Totals().Apps["app"] != (Bytes{7, 11}) || f.ReferencesLine(line) {
		t.Fatal("accounting/refcount changed")
	}
}

func TestProxyDestinationFamilyControlsIPv6AdmissionAndClosure(t *testing.T) {
	f := table(t, Defaults())
	v := tuple
	v.Source = netip.MustParseAddrPort("127.0.0.1:12345")
	v.Destination = netip.MustParseAddrPort("[2001:db8::1]:443")
	x, err := f.Begin("tcp", v)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	if _, err = x.Resolve(platform.Owner{AppID: "proxy"}); err != nil {
		t.Fatal(err)
	}
	closed, err := f.CloseFlows(Selector{IPv6: true}, 0)
	if err != nil || closed.Closed != 1 {
		t.Fatal(closed, err)
	}
	r := revision(2)
	r.Config.IPv6 = false
	r.Hash = policy.Hash(r.Config)
	if _, err := f.Apply(r); err != nil {
		t.Fatal(err)
	}
	if x, err := f.Begin("tcp", v); err == nil {
		x.Close()
		t.Fatal("IPv4 listener bypassed IPv6 policy")
	}
	v.Source = netip.MustParseAddrPort("[::1]:12345")
	v.Destination = tuple.Destination
	x, err = f.Begin("tcp", v)
	if err != nil {
		t.Fatal("IPv6 listener rejected IPv4 target", err)
	}
	x.Close()
}
