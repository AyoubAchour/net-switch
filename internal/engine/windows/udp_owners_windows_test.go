//go:build windows

package winengine

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

func TestUDPNewLookupCannotUseEarlierSocketGeneration(t *testing.T) {
	published := 17 * time.Millisecond
	snapshot := &udpOwnerSnapshot{at: published}
	// All these instants fit in one 16 ms coarse-clock tick. Actual lookup
	// freshness comes from QPC, and a newer query needs a newer native dump.
	for _, test := range []struct {
		after, age time.Duration
		want       bool
	}{
		{published - time.Nanosecond, 0, true},
		{published, 0, false},
		{published + time.Nanosecond, time.Nanosecond, false},
		{published - time.Nanosecond, 5*time.Millisecond - time.Nanosecond, true},
		{published - time.Nanosecond, 5 * time.Millisecond, false},
	} {
		if got := freshUDPSnapshot(snapshot, test.after, published+test.age); got != test.want {
			t.Fatalf("after=%s age=%s got=%t want=%t", test.after, test.age, got, test.want)
		}
	}
}

func TestUDPConcurrentOwnersShareFreshNativeSnapshots(t *testing.T) {
	hosted(t)
	const count = 256
	owners := NewOwners()
	keys := make([]netip.AddrPort, count)
	for i := range keys {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		keys[i] = conn.LocalAddr().(*net.UDPAddr).AddrPort()
	}
	start := make(chan struct{})
	var workers sync.WaitGroup
	results := make([]platform.Owner, count)
	errors := make([]error, count)
	for i := range keys {
		workers.Go(func() {
			<-start
			results[i], errors[i] = owners.UDP(context.Background(), keys[i])
		})
	}
	close(start)
	workers.Wait()
	for i, owner := range results {
		if errors[i] != nil || owner.PID != uint32(os.Getpid()) || owner.Generation == "" {
			t.Fatalf("cold UDP source %s: %+v %v", keys[i], owner, errors[i])
		}
	}
	h := owners.Stats()
	if h.UDPRefreshes >= count/4 {
		t.Fatalf("native dumps were not shared: %d for %d callers", h.UDPRefreshes, count)
	}
	if h.UDPParallelPeak < 1 || h.UDPParallelPeak > ownerParallelReads {
		t.Fatalf("native reads in flight peaked at %d; the bound is %d", h.UDPParallelPeak, ownerParallelReads)
	}
	// A later query must not turn a warm positive row into a generation oracle.
	before := h.UDPRefreshes
	if _, err := owners.UDP(context.Background(), keys[0]); err != nil {
		t.Fatal(err)
	}
	if owners.Stats().UDPRefreshes <= before {
		t.Fatal("a new query reused a native dump started before it")
	}
	t.Logf("%d/%d cold UDP owners, %d native dumps (at most %d in flight); read=%s index=%s; later query forced fresh native data",
		count, count, h.UDPRefreshes, h.UDPParallelPeak, time.Duration(h.UDPReadNanos), time.Duration(h.UDPIndexNanos))
}
