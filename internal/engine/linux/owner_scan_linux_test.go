//go:build linux

package linux

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

func TestCompletedSmallScanDoesNotHideLaterSocket(t *testing.T) {
	o := newTestOwners(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := o.Warm(ctx); err != nil {
		t.Fatal(err)
	}
	var previous string
	for range 2 {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		source := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(conn.LocalAddr().(*net.UDPAddr).Port))
		owner, err := o.UDPFor(ctx, platform.Tuple{Source: source, Destination: netip.MustParseAddrPort("192.0.2.1:443")})
		if err != nil || owner.PID != uint32(os.Getpid()) || owner.Generation == "" || owner.Generation == previous {
			t.Fatalf("fresh socket after completed scan: %+v %v", owner, err)
		}
		previous = owner.Generation
		o.mu.Lock()
		completed := o.windows[owner.PID].fullScan
		o.mu.Unlock()
		if completed.IsZero() {
			t.Fatal("fixture did not establish a completed small descriptor scan")
		}
	}
}

func TestExpiredHolderLookupDoesNotWaitForIndex(t *testing.T) {
	o := newTestOwners(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	o.mu.Lock()
	defer o.mu.Unlock()
	index := o.indexFor(1)
	index.mu.Lock()
	defer index.mu.Unlock()
	done := make(chan error, 1)
	go func() { _, err := o.holders(ctx, socketRow{inode: 1}); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expired lookup: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expired lookup entered shared index work")
	}
}

func TestOwnerIndexPublicationDoesNotWaitForUnrelatedShard(t *testing.T) {
	o := newTestOwners(t)
	const first = uint32(1)
	second := uint32(2)
	for o.indexFor(first) == o.indexFor(second) {
		second++
	}
	waiter := o.subscribe(second)
	defer o.unsubscribe(second, waiter)
	locked := o.indexFor(first)
	locked.mu.Lock()
	defer locked.mu.Unlock()
	want := holder{pid: 42, start: 7, fd: "19"}
	done := make(chan struct{})
	go func() { o.publish(map[uint32]holder{second: want}); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("publishing one inode waited on an unrelated shard")
	}
	select {
	case <-waiter.ready:
	default:
		t.Fatal("published holder did not wake its subscriber")
	}
	if got := o.indexed(second); got.first != want {
		t.Fatalf("published holder: %+v, want %+v", got.first, want)
	}
}
