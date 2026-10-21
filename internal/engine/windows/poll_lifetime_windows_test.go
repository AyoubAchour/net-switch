//go:build windows && netswitch_handlecheck

package winengine

import (
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
)

func pollLifetimePair(t *testing.T) (*readiness, *readySocket) {
	t.Helper()
	pool, err := newReadiness()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pool.close(); err != nil {
			t.Error(err)
		}
	})
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	conn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer, err := listener.Accept()
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	c := &readySocket{blocking: conn.(*net.TCPConn), pool: pool, local: conn.LocalAddr(), remote: conn.RemoteAddr()}
	t.Cleanup(func() { c.Close() })
	if _, err := c.Watch(func() {}); err != nil {
		t.Fatal(err)
	}
	return pool, c
}

func TestTCPWritePollKeepsBorrowUntilNativeQueryReturns(t *testing.T) {
	hosted(t)
	pool, c := pollLifetimePair(t)
	entered, resume := make(chan struct{}), make(chan struct{})
	pool.mu.Lock()
	pool.poll = func(rows []pollFD) int32 {
		close(entered)
		<-resume // Suspend the nonblocking native call at its lifetime boundary.
		return pollWritable(rows)
	}
	pool.mu.Unlock()
	if err := c.watch.Arm(false, true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("write poll did not reach its query")
	}
	closeStarted, closed := make(chan struct{}), make(chan error, 1)
	go func() { close(closeStarted); closed <- c.Close() }()
	<-closeStarted
	early := false
	detaching := false
	deadline := time.Now().Add(time.Second)
	for !early && !detaching && time.Now().Before(deadline) {
		select {
		case err := <-closed:
			early = true
			t.Errorf("Close completed while the native poll still held its copied handle: %v", err)
		default:
			// No receive is armed and the poll is paused before touching the
			// watch mutex. A held watch mutex proves Detach reached its pool
			// borrow fence, rather than Close merely not being scheduled yet.
			if !c.watch.mu.TryLock() {
				detaching = true
			} else {
				c.watch.mu.Unlock()
				runtime.Gosched()
			}
		}
	}
	if !early && !detaching {
		t.Error("fixture never reached Detach during the paused query")
	}
	close(resume)
	if !early {
		select {
		case err := <-closed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("Close did not finish after the native query returned")
		}
	}
	t.Log("Detach/Close waited for the already-started nonblocking write query")
}

func TestOldUnlockedPollSnapshotTripsEndedGeneration(t *testing.T) {
	hosted(t)
	pool, c := pollLifetimePair(t)
	// Reproduce the old ordering without issuing an unsafe OS call: snapshot,
	// unlock, then let Close finish before attempting to use the saved value.
	pool.mu.Lock()
	borrowed := c.watch.socket
	borrowed.Handle("old TCP write poll snapshot")
	pool.mu.Unlock()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		value := recover()
		if value == nil || !strings.Contains(value.(string), "use of an ended or replaced generation") {
			t.Fatalf("negative control failed to detect the old poll ordering: %v", value)
		}
		t.Logf("old unlocked ordering detected before WSAPoll: %v", value)
	}()
	borrowed.Handle("old TCP write poll query")
}
