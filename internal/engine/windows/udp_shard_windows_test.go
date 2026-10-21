//go:build windows

package winengine

import (
	"bytes"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestUDPShardPollKeepsBorrowAndOtherWaiterProgress(t *testing.T) {
	hosted(t)
	first, peer := nativeUDPPair(t, "udp4")
	pool := first.pool
	firstWatch, err := first.Watch(func() {})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	second := &udpSocket{conn: conn, raw: raw, pool: pool, local: conn.LocalAddr().(*net.UDPAddr).AddrPort(), mtu: 65535}
	t.Cleanup(func() {
		if err := second.Close(); err != nil {
			t.Error(err)
		}
	})
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
	if first.watch.shard == second.watch.shard {
		t.Fatal("fixture needs distinct shards")
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
