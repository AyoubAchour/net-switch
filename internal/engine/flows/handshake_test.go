package flows

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

// Every flow counted in Handshakes is listed with its owner, before and after
// its owner is resolved, and leaves the list when established or retired.
func TestHandshakeFlowsListEveryHandshakeWithItsOwner(t *testing.T) {
	f := table(t, Defaults())
	x, err := f.Begin("tcp", tuple)
	if err != nil {
		t.Fatal(err)
	}
	list := f.HandshakeFlows()
	if len(list) != 1 || list[0].Resolved || list[0].Owner.AppID != "" || list[0].Source != tuple.Source {
		t.Fatalf("unresolved handshake: %+v", list)
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
	list = f.HandshakeFlows()
	if len(list) != 2 || !list[0].Resolved || list[0].Owner != owner || list[0].Line != "B" || list[1].Owner.AppID != "" {
		t.Fatalf("resolved handshakes: %+v", list)
	}
	page, err := f.Page("")
	if err != nil || len(page.Flows) != 2 || !page.Flows[0].Handshake || !page.Flows[1].Handshake {
		t.Fatalf("listed flows lack the handshake state: %+v %v", page.Flows, err)
	}
	x.Established(netip.MustParseAddr("192.0.2.1"))
	list = f.HandshakeFlows()
	if len(list) != 1 || list[0].Source != other.Source || f.Stats().Handshakes != 1 {
		t.Fatalf("after establishing: %+v gauge %d", list, f.Stats().Handshakes)
	}
	page, err = f.Page("")
	if err != nil || len(page.Flows) != 2 || page.Flows[0].Handshake || !page.Flows[1].Handshake {
		t.Fatalf("listed flows after establishing: %+v %v", page.Flows, err)
	}
	y.Retire()
	if list := f.HandshakeFlows(); len(list) != 0 || f.Stats().Handshakes != 0 {
		t.Fatalf("after retiring: %+v gauge %d", list, f.Stats().Handshakes)
	}
	x.Close()
	y.Close()
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
