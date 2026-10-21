//go:build linux

package linux

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"sync"
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
		// Complete a negative pass before creating the socket. A successful
		// targeted lookup may stop at its match without reaching directory EOF.
		pid := uint32(os.Getpid())
		o.rememberPID(uint32(os.Getuid()), pid)
		o.mu.Lock()
		window := o.windows[pid]
		window.next = 0 // establish a full pass, not EOF after a retained cursor
		o.windows[pid] = window
		o.mu.Unlock()
		began := time.Now()
		prime, stop := context.WithTimeout(ctx, 100*time.Millisecond)
		_, primeErr := o.holders(prime, socketRow{inode: 1, uid: uint32(os.Getuid())})
		stop()
		if !errors.Is(primeErr, os.ErrNotExist) && !errors.Is(primeErr, context.DeadlineExceeded) {
			t.Fatalf("negative scan: %v", primeErr)
		}
		o.mu.Lock()
		completed := o.windows[pid].fullScan
		o.mu.Unlock()
		if completed.Before(began) {
			t.Fatal("fixture did not establish a completed small descriptor scan")
		}
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
	}
}

func TestMatchedHolderDoesNotWaitForBatchCompletion(t *testing.T) {
	o := newTestOwners(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := o.Warm(ctx); err != nil {
		t.Fatal(err)
	}
	// Sockets already open below ours, as earlier tests can leave them until
	// the collector closes them, come first in the directory. Hold 96 so that
	// layout is always present: the target must be chosen by visit order, not
	// assumed to lie in the first 64 sockets.
	for range 72 {
		earlier, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
		if err != nil {
			t.Fatal(err)
		}
		defer earlier.Close()
	}
	var rows []socketRow
	var descriptors []int
	for range 256 {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		raw, err := conn.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var st unix.Stat_t
		var statErr error
		var fd int
		if err := raw.Control(func(value uintptr) { fd = int(value); statErr = unix.Fstat(fd, &st) }); err != nil || statErr != nil {
			t.Fatalf("socket metadata: %v %v", err, statErr)
		}
		descriptors = append(descriptors, fd)
		rows = append(rows, socketRow{inode: uint32(st.Ino), uid: st.Uid, protocol: unix.IPPROTO_UDP})
	}
	pid := uint32(os.Getpid())
	start, err := processStart(pid)
	if err != nil {
		t.Fatal(err)
	}
	var directory unix.Stat_t
	if err := unix.Stat("/proc/self/fd", &directory); err != nil {
		t.Fatal(err)
	}
	if descriptors[255] < 128 || descriptors[1] <= descriptors[0] {
		t.Fatal("fixture did not establish an ordered large descriptor set")
	}
	o.windows[pid] = fdWindow{start: start, directory: directory.Ino, lastFD: -1, extent: int64(descriptors[255])}
	o.rememberPID(rows[0].uid, pid)
	// Block publication after the target, on a shard that no socket at or
	// before the target uses: the scanner publishes every socket it passes,
	// so only then can the match finish while the later work is stuck. The
	// target is our first socket in directory order, wherever it falls.
	own := map[uint32]int{}
	for i, row := range rows {
		own[row.inode] = i
	}
	dir, err := openProcDescriptors("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	// UDP cookie hints share the inode index's 64 shard mutexes, and a UDP
	// lookup reads its cookie's shard before it scans. Every row here has
	// cookie zero; exclude that shard too, or about one run in 64 (the seed
	// is random) blocks the lookup before scanning, not the later publication.
	upToTarget := map[*ownerIndex]bool{o.cookieIndex(rows[0].cookie): true}
	oldFirst := map[*ownerIndex]bool{}
	var blocked, oldBlocked *ownerIndex
	var blockedInode uint32
	target, targetAt, blockedAt, oldBlockedAt, blockedFD, count := -1, -1, -1, -1, -1, 0
	_, visitErr := dir.Visit(4096, func(name []byte) bool {
		inode, ok := socketInodeAt(dir.fd, string(name))
		if !ok {
			return true
		}
		shard := o.indexFor(inode)
		// The fixture this replaces took the first 64 sockets as the ones
		// before the target; keep its choice for the log.
		if count < 64 {
			oldFirst[shard] = true
		} else if oldBlocked == nil && !oldFirst[shard] {
			oldBlocked, oldBlockedAt = shard, count
		}
		if i, mine := own[inode]; mine && target < 0 {
			target, targetAt = i, count
		}
		if target < 0 || targetAt == count {
			upToTarget[shard] = true
		} else if blocked == nil && !upToTarget[shard] {
			blocked, blockedInode, blockedAt = shard, inode, count
			blockedFD, _ = strconv.Atoi(string(name))
		}
		count++
		return blocked == nil || oldBlocked == nil
	})
	dir.Close()
	t.Logf("socket order: target row %d at %d, blocked at %d (fd %d); the old first-64 fixture blocked at %d, before the target=%t, would pass=%t",
		target, targetAt, blockedAt, blockedFD, oldBlockedAt, oldBlockedAt >= 0 && oldBlockedAt < targetAt, oldBlocked != nil && oldFirst[o.indexFor(rows[0].inode)] && oldBlockedAt > targetAt)
	// The scan below reads new descriptors in one 512-entry window, so the
	// blocked socket must fall inside it for its batch to stay pending.
	if (visitErr != nil && !errors.Is(visitErr, io.EOF)) || target < 0 || blocked == nil || targetAt < 64 || blockedFD < 0 || blockedFD >= 512 {
		t.Fatalf("fixture did not find an independent shard after a target past the first 64 sockets, inside the first window: %v", visitErr)
	}
	blocked.mu.Lock()
	locked := true
	defer func() {
		if locked {
			blocked.mu.Unlock()
		}
	}()
	type result struct {
		owner platform.Owner
		err   error
	}
	done := make(chan result, 1)
	go func() {
		owner, err := o.holders(ctx, rows[target])
		done <- result{owner, err}
	}()
	select {
	case got := <-done:
		if got.err != nil || got.owner.PID != pid {
			t.Fatalf("first live descriptor: %+v %v", got.owner, got.err)
		}
	case <-time.After(time.Second):
		stacks := make([]byte, 64<<10)
		n := runtime.Stack(stacks, true)
		t.Fatalf("matched owner waited for unrelated descriptor publication; goroutines:\n%s", stacks[:n])
	}
	o.batches.liveMu.Lock()
	var batch *descriptorBatch
	for key, candidate := range o.batches.live {
		if key.pid == pid {
			batch = candidate
			break
		}
	}
	o.batches.liveMu.Unlock()
	if batch == nil {
		t.Fatal("fixture did not leave its later descriptor batch pending")
	}
	select {
	case <-batch.done:
		t.Fatal("fixture batch completed before releasing its blocked shard")
	default:
	}
	blocked.mu.Unlock()
	locked = false
	select {
	case <-batch.done:
	case <-time.After(time.Second):
		t.Fatal("descriptor batch did not finish after publication resumed")
	}
	if o.indexed(blockedInode).count() == 0 {
		t.Fatal("returning the first match discarded the later socket hint")
	}
	owner, err := o.holders(ctx, socketRow{inode: blockedInode, uid: rows[0].uid, protocol: unix.IPPROTO_UDP})
	if err != nil || owner.PID != pid {
		t.Fatalf("later published descriptor: %+v %v", owner, err)
	}
}

func TestRequestedDescriptorPublishesBeforeUnrelatedChecks(t *testing.T) {
	o := newTestOwners(t)
	earlier := map[*ownerIndex]bool{}
	before, err := openProcDescriptors("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	_, err = before.Visit(4096, func(name []byte) bool {
		if inode, ok := socketInodeAt(before.fd, string(name)); ok {
			earlier[o.indexFor(inode)] = true
		}
		return true
	})
	before.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	var target uint32
	var blocked *ownerIndex
	for range 16 {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		raw, err := conn.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var st unix.Stat_t
		var statErr error
		if err := raw.Control(func(fd uintptr) { statErr = unix.Fstat(int(fd), &st) }); err != nil || statErr != nil {
			t.Fatalf("real socket metadata: %v %v", err, statErr)
		}
		inode := uint32(st.Ino)
		if target == 0 {
			target = inode
		} else if o.indexFor(inode) != o.indexFor(target) && !earlier[o.indexFor(inode)] {
			blocked = o.indexFor(inode)
			break
		}
	}
	if blocked == nil {
		t.Fatal("fixture could not create a later socket in a separate index shard")
	}
	dir, err := openProcDescriptors("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	passedTarget, reachedBlock := false, false
	_, err = dir.Visit(128, func(name []byte) bool {
		inode, ok := socketInodeAt(dir.fd, string(name))
		if !ok {
			return true
		}
		passedTarget = passedTarget || inode == target
		if o.indexFor(inode) == blocked {
			reachedBlock = true
			return false
		}
		return true
	})
	dir.Close()
	if err != nil || !passedTarget || !reachedBlock {
		t.Fatalf("fixture must encounter the requested socket before the blocked shard: %v", err)
	}
	pid := uint32(os.Getpid())
	start, err := processStart(pid)
	if err != nil {
		t.Fatal(err)
	}
	var directory unix.Stat_t
	if err := unix.Stat("/proc/self/fd", &directory); err != nil {
		t.Fatal(err)
	}
	notice := o.subscribe(target)
	defer o.unsubscribe(target, notice)
	blocked.mu.Lock()
	unlock := sync.OnceFunc(blocked.mu.Unlock)
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// A foreign-process scan retains only requested hints. Checking the next
	// socket's subscribers is blocked; our earlier live match must be visible
	// before that check, not after 32 matches or the whole directory finishes.
	key := descriptorBatchKey{pid: pid, start: start, directory: directory.Ino, limit: 128}
	job, err := o.descriptorBatch(ctx, key, time.Now(), false)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-notice.ready:
		if o.indexed(target).count() != 1 {
			t.Fatal("notification did not carry the real descriptor hint")
		}
	case <-time.After(time.Second):
		t.Fatal("requested socket waited for an unrelated descriptor check")
	}
	select {
	case <-job.done:
		t.Fatal("fixture did not keep later descriptor work blocked")
	default:
	}
	unlock()
	select {
	case <-job.done:
	case <-time.After(time.Second):
		t.Fatal("descriptor scan did not finish after releasing the unrelated shard")
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

func TestRecentHolderSnapshotsStayImmutableDuringUpdates(t *testing.T) {
	o := newTestOwners(t)
	for pid := uint32(1); pid <= 32; pid++ {
		o.rememberPID(1000, pid)
	}
	snapshot := o.recentPIDs(1000)
	if len(snapshot) != 32 || snapshot[0] != 32 || snapshot[31] != 1 {
		t.Fatal("fixture did not fill the bounded hint list")
	}
	var writers sync.WaitGroup
	for i := uint32(0); i < 8; i++ {
		writers.Go(func() {
			for pid := uint32(33); pid < 200; pid++ {
				o.rememberPID(1000, pid+i*200)
			}
		})
	}
	for range 1000 {
		for i, pid := range snapshot {
			if pid != uint32(32-i) {
				t.Error("writer changed a published snapshot")
				break
			}
		}
		current := o.recentPIDs(1000)
		seen := map[uint32]bool{}
		for _, pid := range current {
			if pid == 0 || seen[pid] {
				t.Error("hint list contains a zero or duplicate PID")
			}
			seen[pid] = true
		}
		if len(current) > 32 {
			t.Error("hint list exceeded its bound")
		}
	}
	writers.Wait()
}
