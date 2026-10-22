//go:build windows

package winengine

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func socketInUDPTestPool(t *testing.T, pool *udpReadiness) *udpSocket {
	t.Helper()
	socket, err := openUDP(loopbackLine(t), netip.MustParseAddrPort("127.0.0.2:0"), pool)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := socket.Close(); err != nil {
			t.Error(err)
		}
	})
	return socket
}

func TestUDPShardPollKeepsBorrowAndOtherWaiterProgress(t *testing.T) {
	hosted(t)
	first, peer := nativeUDPPair(t, "udp4")
	pool := first.pool
	firstWatch, err := first.Watch(func() {})
	if err != nil {
		t.Fatal(err)
	}
	second := socketInUDPTestPool(t, pool)
	wake := make(chan struct{}, 1)
	secondWatch, err := second.Watch(func() {
		select {
		case wake <- struct{}{}:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.watch.shard != &pool.shards[0] || second.watch.shard != &pool.shards[1] || udpWaiters < 2 {
		t.Fatal("fixture needs shards on distinct waiters")
	}
	entered, resume := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(resume) })
	defer release()
	var paused atomic.Bool
	handle := first.handle.Handle("UDP poll lifetime fixture")
	pool.poll = func(rows []pollFD) (int32, error) {
		if len(rows) > udpShardCapacity {
			t.Errorf("native poll exceeded shard bound: %d", len(rows))
		}
		for _, row := range rows {
			if row.Socket == handle && paused.CompareAndSwap(false, true) {
				close(entered)
				<-resume
				break
			}
		}
		return pollUDP(rows)
	}
	if err := firstWatch.Arm(true, false); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("query did not reach pause")
	}
	closed := make(chan error, 1)
	go func() { closed <- first.Close() }()
	closeEntered := false
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if !first.mu.TryLock() {
			closeEntered = true
			break
		}
		first.mu.Unlock()
		runtime.Gosched()
	}
	if !closeEntered {
		t.Error("Close never reached its socket lock")
	}
	select {
	case err := <-closed:
		t.Fatalf("Close passed an in-flight native query: %v", err)
	default:
	}
	armed := make(chan error, 1)
	go func() { armed <- secondWatch.Arm(true, false) }()
	select {
	case err := <-armed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("one shard's native query blocked another waiter's Arm")
	}
	payload := []byte("other shard progresses")
	if _, err := peer.WriteToUDPAddrPort(payload, second.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	udpWake(t, wake)
	var b [64]byte
	n, from, err := second.TryReadFrom(b[:])
	if err != nil || from != peer.LocalAddr().(*net.UDPAddr).AddrPort() || !bytes.Equal(b[:n], payload) {
		t.Fatalf("other shard reply: %d %s %v", n, from, err)
	}
	release()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close stayed blocked after query returned")
	}
	t.Log("paused native query fenced Close while the other waiter delivered an exact datagram")
}

func TestUDPShardFailureWakesEveryArmedMapping(t *testing.T) {
	hosted(t)
	injected := errors.New("injected UDP poll failure")
	fatal := make(chan error, 1)
	pool, err := newUDPReadiness(func(err error) { fatal <- err })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pool.close(); !errors.Is(err, injected) {
			t.Errorf("pool close lost its failure: %v", err)
		}
	})
	var fail atomic.Bool
	pool.poll = func(rows []pollFD) (int32, error) {
		if fail.Load() {
			return -1, injected
		}
		return pollUDP(rows)
	}
	wakes := make(chan int, udpShardCount*2)
	watches := make([]*udpWatch, udpShardCount)
	for i := range watches {
		socket := socketInUDPTestPool(t, pool)
		_, err := socket.Watch(func() { wakes <- i })
		if err != nil {
			t.Fatal(err)
		}
		watches[i] = socket.watch
		if socket.watch.shard != &pool.shards[i] {
			t.Fatal("fixture failed to cover every shard")
		}
		if err := socket.watch.Arm(true, false); err != nil {
			t.Fatal(err)
		}
	}
	fail.Store(true)
	if err := windows.SetEvent(pool.shards[0].event.Handle("UDP failure fixture wake")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-fatal:
		if !errors.Is(err, injected) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pool failure did not finish its notification")
	}
	joined := make(chan struct{})
	go func() { pool.wg.Wait(); close(joined) }()
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("failed waiters did not exit")
	}
	seen := make(map[int]bool)
	for len(wakes) != 0 {
		i := <-wakes
		if seen[i] {
			t.Errorf("mapping %d woke twice", i)
		}
		seen[i] = true
	}
	if len(seen) != udpShardCount {
		t.Fatalf("failure woke %d of %d armed mappings", len(seen), udpShardCount)
	}
	for _, watch := range watches {
		if err := watch.Arm(true, false); !errors.Is(err, injected) {
			t.Fatalf("rearm lost the pool failure: %v", err)
		}
	}
}
