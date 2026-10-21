//go:build windows

package winengine

import (
	"net"
	"runtime"
	"testing"
	"time"
)

type pollCallbackLifetime struct{ bytes [1024]byte }

func closeCallbackPair(t *testing.T, pool *readiness, polled bool) <-chan struct{} {
	t.Helper()
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
	defer peer.Close()
	c := &readySocket{blocking: conn.(*net.TCPConn), pool: pool, local: conn.LocalAddr(), remote: conn.RemoteAddr()}
	defer c.Close()
	collected := make(chan struct{})
	lifetime := new(pollCallbackLifetime)
	runtime.AddCleanup(lifetime, func(done chan struct{}) { close(done) }, collected)
	woke := make(chan struct{}, 1)
	watch, err := c.Watch(func() {
		runtime.KeepAlive(lifetime)
		select {
		case woke <- struct{}{}:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if polled {
		if err := watch.Arm(false, true); err != nil {
			t.Fatal(err)
		}
		select {
		case <-woke:
		case <-time.After(time.Second):
			t.Fatal("callback never entered the native write-poll snapshot")
		}
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	return collected
}

func TestTCPWritePollReleasesDetachedCallback(t *testing.T) {
	hosted(t)
	pool, err := newReadiness()
	if err != nil {
		t.Fatal(err)
	}
	defer pool.close()
	for _, polled := range []bool{false, true} {
		collected := closeCallbackPair(t, pool, polled)
		deadline := time.Now().Add(2 * time.Second)
		done := false
		for !done && time.Now().Before(deadline) {
			runtime.GC()
			select {
			case <-collected:
				done = true
			case <-time.After(10 * time.Millisecond):
			}
		}
		if !done {
			t.Fatalf("closed callback remained reachable while the poller stayed alive; polled=%t", polled)
		}
		t.Logf("closed callback collected while the same poller remained alive; polled=%t", polled)
	}
	runtime.KeepAlive(pool)
}
