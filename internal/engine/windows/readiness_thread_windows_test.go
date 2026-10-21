//go:build windows

package winengine

import (
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestCompletionPortKeepsItsOSThread(t *testing.T) {
	hosted(t)
	pool, err := newReadiness()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := pool.close(); err != nil {
			t.Error(err)
		}
	}()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.Accept()
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	defer server.Close()
	c := &readySocket{blocking: client.(*net.TCPConn), pool: pool, local: client.LocalAddr(), remote: client.RemoteAddr()}
	defer c.Close()
	wakes := make(chan uint32, 1)
	var duplicate atomic.Uint32
	watch, err := c.Watch(func() {
		select {
		case wakes <- windows.GetCurrentThreadId():
		default:
			duplicate.Add(1)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	for round := range 256 {
		// The socket is empty at Arm, so this exercises an actual queued
		// completion, not Arm's inline-success callback on the caller's thread.
		if err := watch.Arm(true, false); err != nil {
			t.Fatal(err)
		}
		runtime.Gosched()
		if _, err := server.Write([]byte{byte(round)}); err != nil {
			t.Fatal(err)
		}
		select {
		case thread := <-wakes:
			if thread == 0 || thread != pool.thread.Load() {
				t.Fatalf("completion moved OS threads: initial=%d current=%d", pool.thread.Load(), thread)
			}
		case <-time.After(time.Second):
			t.Fatal("queued completion stalled")
		}
		if n, err := c.TryRead(b[:]); err != nil || n != 1 || b[0] != byte(round) {
			t.Fatalf("round %d: byte=%d count=%d err=%v", round, b[0], n, err)
		}
	}
	if duplicate.Load() != 0 {
		t.Fatalf("duplicate completions: %d", duplicate.Load())
	}
	t.Logf("256 queued completions stayed on OS thread %d", pool.thread.Load())
}
