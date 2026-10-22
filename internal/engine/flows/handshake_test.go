package flows

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

// listAll pages a full listing to its end and returns its records and the
// table's counts from the first page.
func listAll(t *testing.T, f *Table) ([]Record, Counted) {
	t.Helper()
	page, err := f.PageAll("")
	if err != nil || page.Counted == nil {
		t.Fatalf("full listing: %+v %v", page.Counted, err)
	}
	counted, records := *page.Counted, page.Flows
	for page.Cursor != "" {
		if page, err = f.PageAll(page.Cursor); err != nil {
			t.Fatal(err)
		}
		if page.Counted != nil {
			t.Fatal("counts repeated on a later page")
		}
		records = append(records, page.Flows...)
	}
	return records, counted
}

// Every flow counted in Handshakes is in the full listing with its owner,
// before and after its owner is resolved, and leaves the handshake state when
// established or retired. The ordinary listing still shows resolved flows only.
func TestFullListingShowsEveryHandshakeWithItsOwner(t *testing.T) {
	f := table(t, Defaults())
	x, err := f.Begin("tcp", tuple)
	if err != nil {
		t.Fatal(err)
	}
	all, counted := listAll(t, f)
	if len(all) != 1 || !all[0].Unresolved || !all[0].Handshake || all[0].Owner.AppID != "" || all[0].Source != tuple.Source ||
		counted != (Counted{Flows: 1, Handshakes: 1}) {
		t.Fatalf("unresolved handshake: %+v %+v", all, counted)
	}
	if page, err := f.Page(""); err != nil || len(page.Flows) != 0 || page.Counted != nil {
		t.Fatalf("the ordinary listing showed an unresolved flow: %+v %v", page, err)
	}
	owner := platform.Owner{PID: 42, Path: `C:\apps\pinned.exe`, AppID: "pinned"}
	if _, err := x.Resolve(owner); err != nil {
		t.Fatal(err)
	}
	other := platform.Tuple{Source: netip.MustParseAddrPort("198.18.0.2:40001"), Destination: tuple.Destination}
	y, err := f.Begin("tcp", other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := y.Resolve(platform.Owner{}); err != nil {
		t.Fatal(err)
	}
	u, err := f.Begin("udp", platform.Tuple{Source: netip.MustParseAddrPort("198.18.0.2:5353"), Destination: tuple.Destination})
	if err != nil {
		t.Fatal(err)
	}
	all, counted = listAll(t, f)
	if len(all) != 3 || all[0].Unresolved || all[0].Owner != owner || all[0].Line != "B" || !all[0].Handshake ||
		all[1].Owner.AppID != "" || !all[1].Handshake || !all[2].Unresolved || all[2].Handshake ||
		counted != (Counted{Flows: 3, UDP: 1, Handshakes: 2}) {
		t.Fatalf("resolved handshakes: %+v %+v", all, counted)
	}
	page, err := f.Page("")
	if err != nil || len(page.Flows) != 2 || !page.Flows[0].Handshake || !page.Flows[1].Handshake {
		t.Fatalf("listed flows lack the handshake state: %+v %v", page.Flows, err)
	}
	x.Established(netip.MustParseAddr("192.0.2.1"))
	all, counted = listAll(t, f)
	if len(all) != 3 || all[0].Handshake || !all[1].Handshake || counted.Handshakes != 1 || f.Stats().Handshakes != 1 {
		t.Fatalf("after establishing: %+v %+v", all, counted)
	}
	y.Retire()
	u.Close()
	all, counted = listAll(t, f)
	if len(all) != 1 || all[0].ID != 1 || counted != (Counted{Flows: 1}) || f.Stats().Handshakes != 0 {
		t.Fatalf("after retiring: %+v %+v", all, counted)
	}
	x.Close()
	y.Close()
	if f.Stats().SnapshotBytes != 0 {
		t.Fatal("snapshot bytes leaked")
	}
}

// Admission keeps its cost: a flow is one ticket and no other allocation.
// This same loop measured 1 allocation on main 95e68bdd and on 5b502222; the
// handshake set 5b502222 kept beside the gauge added map upkeep per flow
// without new allocations, so it was removed rather than measured here.
func TestBeginAllocations(t *testing.T) {
	f := table(t, Defaults())
	for _, protocol := range []string{"tcp", "udp"} {
		warm, err := f.Begin(protocol, tuple)
		if err != nil {
			t.Fatal(err)
		}
		warm.Close()
		allocs := testing.AllocsPerRun(1000, func() {
			x, err := f.Begin(protocol, tuple)
			if err != nil {
				t.Fatal(err)
			}
			x.Close()
		})
		if allocs > 1 {
			t.Fatalf("%s Begin and Close allocate %.1f times, want 1 (the ticket)", protocol, allocs)
		}
	}
}

// SYSTEM-DESIGN 5: the snapshot budget follows the flow limit, so all 65,536
// flows list in one snapshot even when every owner uses its full byte limit.
func TestPageListsEveryFlowAtTheFlowLimit(t *testing.T) {
	l := Defaults()
	l.TCPBytes = 1 << 40 // this test is about the snapshot, not relay buffers
	f := table(t, l)
	apps := l.Flows / l.PerApp
	owners := make([]platform.Owner, apps)
	for i := range owners {
		id := fmt.Sprintf("app%d-", i)
		owners[i] = platform.Owner{PID: uint32(i + 1), Path: strings.Repeat("p", 1024),
			AppID: id + strings.Repeat("a", 512-len(id)), Generation: strings.Repeat("g", 256)}
	}
	tickets := make([]flowapi.Ticket, 0, l.Flows)
	defer func() {
		for _, x := range tickets {
			x.Close()
		}
	}()
	for n := range l.Flows {
		source := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(n >> 16), byte(n >> 8)}), uint16(10000+n&0xff))
		x, err := f.Begin("tcp", platform.Tuple{Source: source, Destination: tuple.Destination})
		if err != nil {
			t.Fatalf("flow %d: %v", n, err)
		}
		tickets = append(tickets, x)
		if _, err := x.Resolve(owners[n%apps]); err != nil {
			t.Fatalf("flow %d: %v", n, err)
		}
		x.Established(netip.Addr{})
	}
	seen := map[uint64]bool{}
	page, err := f.Page("")
	for {
		if err != nil {
			t.Fatalf("after %d flows: %v", len(seen), err)
		}
		for _, r := range page.Flows {
			seen[r.ID] = true
		}
		if page.Cursor == "" {
			break
		}
		page, err = f.Page(page.Cursor)
	}
	if len(seen) != l.Flows {
		t.Fatalf("listed %d of %d flows", len(seen), l.Flows)
	}
	if f.Stats().SnapshotBytes != 0 {
		t.Fatal("snapshot bytes leaked")
	}
}
