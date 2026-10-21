package udp

import (
	"context"
	"errors"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
)

type failedSetupControl struct {
	*flows.Table
	observed chan bool
}

func TestDestroyFinishesAcrossFailedSetupCachePublication(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		c := &testfake.Controller{}
		n := &NAT{control: c, now: time.Now}
		ticket, _ := c.Begin("udp", platform.Tuple{})
		defer ticket.Close()
		s := &session{n: n, source: local, owner: owner, ticket: ticket, done: make(chan struct{})}
		b := n.bucket(local)
		b.m = map[netip.AddrPort]*session{local: s}
		// Destroy has obtained s under the shard lock. Before it acquires
		// s.mu, setup fails, publishes the cache entry and finishes cleanup.
		s.rejectPending(owner.AppID)
		s.close()
		if len(b.m) != 0 || len(b.negative) != 1 {
			t.Fatal("fixture did not publish the failed setup cache")
		}
		if replacement {
			entry := b.negative[local]
			entry.owner.Generation = "new socket"
			b.negative[local] = entry
		}
		s.destroyGeneration(owner.Generation)
		_, retained := b.negative[local]
		if retained != replacement {
			t.Fatal("destroy retained an old generation or removed its replacement")
		}
	}
}

func (c *failedSetupControl) AllowReject(string) bool {
	st := c.Stats()
	page, err := c.Page("")
	c.observed <- st.Flows == 0 && st.UDP == 0 && err == nil && len(page.Flows) == 0
	return false
}

func TestFailedUDPSetupRetiresBeforeRefusalAndBoundsNegativeCache(t *testing.T) {
	c := &failedSetupControl{Table: flows.New(flows.Defaults(), nil), observed: make(chan bool, 1)}
	cfg := policy.Config{Lines: []platform.Line{{ID: "A"}}, IPv6: true}
	if _, err := c.Apply(policy.Revision{N: 1, Hash: policy.Hash(cfg), Config: cfg}); err != nil {
		t.Fatal(err)
	}
	n := New(context.Background(), nil, c, &testfake.Owners{Value: owner}, nil, testfake.Dialer{UDPFunc: func(context.Context, string, bool) (platform.UDPConn, error) {
		return nil, errors.New("native socket allocation failed")
	}}, testfake.Output{}, 9000)
	defer n.Close()
	baseline := runtime.NumGoroutine()
	for i := 0; i < RejectCacheEntries*2; i++ {
		source := netip.AddrPortFrom(local.Addr(), uint16(10000+i))
		n.receive(source, dest, 58, func() ([]byte, []byte, bool) { return []byte("x"), packet.UDP(source, dest, []byte("x")), false })
		if !await(t, c.observed) {
			t.Fatal("refusal exposed a phantom flow in count or pagination")
		}
	}
	count := 0
	for i := range n.table {
		b := &n.table[i]
		b.Lock()
		if len(b.negative) > RejectCacheEntries/shards {
			t.Fatal("negative cache shard exceeded cap")
		}
		count += len(b.negative)
		b.Unlock()
	}
	if count == 0 || count > RejectCacheEntries {
		t.Fatalf("cache fixture/bound: %d", count)
	}
	if n.OpenFailed.Load() != RejectCacheEntries*2 {
		t.Fatal("fixture did not execute every native open failure")
	}
	if c.Stats().RefusedUDP.Unexplained != RejectCacheEntries*2 || n.Rejected.Load() != RejectCacheEntries*2 {
		t.Fatal("native setup refusals were missing or mislabeled as cap refusals")
	}
	if got := runtime.NumGoroutine(); got > baseline+8 {
		t.Fatalf("parked failure goroutines: baseline=%d now=%d", baseline, got)
	}
	t.Logf("8192 failed opens; zero rows/count at each refusal; negative entries=%d/%d; goroutines baseline=%d now=%d", count, RejectCacheEntries, baseline, runtime.NumGoroutine())
	// Shared expiry also works when no more packets arrive.
	for i := range n.table {
		b := &n.table[i]
		b.Lock()
		for key, entry := range b.negative {
			entry.at = time.Now().Add(-2 * RejectLifetime)
			b.negative[key] = entry
		}
		b.Unlock()
	}
	n.Reconcile(context.Background())
	for i := range n.table {
		b := &n.table[i]
		b.Lock()
		left := len(b.negative)
		b.Unlock()
		if left != 0 {
			t.Fatal("shared expiry retained negative entries")
		}
	}
}
