//go:build linux

package linux

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"golang.org/x/sys/unix"
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

func TestRelativeSocketInodeUsesTheLiveProcDescriptor(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var fd int
	var st unix.Stat_t
	var statErr error
	if err := raw.Control(func(value uintptr) { fd = int(value); statErr = unix.Fstat(fd, &st) }); err != nil || statErr != nil {
		t.Fatalf("read socket inode: %v %v", err, statErr)
	}
	dir, err := os.Open("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	name := strconv.Itoa(fd)
	for _, location := range []struct {
		dir  int
		name string
	}{{int(dir.Fd()), name}, {unix.AT_FDCWD, "/proc/self/fd/" + name}} {
		if inode, ok := socketInodeAt(location.dir, location.name); !ok || uint64(inode) != st.Ino {
			t.Fatalf("live descriptor lookup: %d %t, want %d", inode, ok, st.Ino)
		}
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := socketInodeAt(int(dir.Fd()), name); ok {
		t.Fatal("closed descriptor remained a socket hint")
	}
	if _, ok := socketInodeAt(int(dir.Fd()), "../exe"); ok {
		t.Fatal("relative scan accepted a non-numeric entry")
	}
}

func TestProcScratchSurvivesCollectionWithinItsBound(t *testing.T) {
	var pool procScratch[[16 << 10]byte]
	var held [65]*[16 << 10]byte
	for i := range held {
		held[i] = pool.Get()
	}
	for _, b := range held {
		pool.Put(b)
	}
	if pool.count != 64 {
		t.Fatalf("retained %d scratch buffers, want 64", pool.count)
	}
	want := held[63]
	runtime.GC()
	runtime.GC()
	if got := pool.Get(); got != want {
		t.Fatal("collection discarded the bounded lookup scratch cache")
	}
}
