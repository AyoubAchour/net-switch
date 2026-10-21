//go:build windows

package winengine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

func completionTestPool(t *testing.T, policy tcpCompletionPolicy) *readiness {
	t.Helper()
	p, err := newReadinessWithPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.close(); err != nil {
			t.Error(err)
		}
	})
	return p
}

// Every client below comes from the engine's own constructor (dialNative):
// a fresh native socket whose completion mode was set only by register. A
// wrong mode cannot pass exerciseTCPCompletionStream: a suppressed packet the
// watch waits for stalls the stream, and an unexpected packet panics the
// completion thread.

func waitCompletionWake(t *testing.T, wakes <-chan uint32) uint32 {
	t.Helper()
	select {
	case thread := <-wakes:
		return thread
	case <-time.After(5 * time.Second):
		t.Fatal("readiness callback timed out")
		return 0
	}
}

func completionThreadWake(wakes chan<- uint32) func() {
	return func() {
		select {
		case wakes <- windows.GetCurrentThreadId():
		default:
			panic("unexpected readiness callback overflow")
		}
	}
}

func waitQueuedTCPData(t *testing.T, c *readySocket) {
	t.Helper()
	var first [1]byte
	deadline := time.Now().Add(5 * time.Second)
	for {
		n, err := c.TryPeek(first[:])
		if n == 1 && err == nil {
			return
		}
		if !errors.Is(err, platform.ErrWouldBlock) || time.Now().After(deadline) {
			t.Fatalf("data was not queued before synchronous receive: n=%d err=%v", n, err)
		}
		time.Sleep(time.Millisecond)
	}
}

func armImmediateTCP(t *testing.T, c *readySocket, wakes <-chan uint32) {
	t.Helper()
	immediate, packets := c.pool.immediate.Load(), c.pool.completed.Load()
	if err := c.watch.Arm(true, false); err != nil {
		t.Fatal(err)
	}
	thread := waitCompletionWake(t, wakes)
	if c.pool.immediate.Load() != immediate+1 {
		t.Fatal("preloaded zero-byte WSARecv did not return synchronous success; no retry")
	}
	expectedPackets := packets
	if !c.watch.skipSuccess {
		expectedPackets++
		if thread != c.pool.thread.Load() {
			t.Fatalf("ordinary synchronous success woke off the completion thread: %d", thread)
		}
	}
	if got := c.pool.completed.Load(); got != expectedPackets {
		t.Fatalf("synchronous success packets=%d want=%d skip=%t", got, expectedPackets, c.watch.skipSuccess)
	}
}

func exerciseTCPCompletionStream(t *testing.T, c *readySocket, peer *net.TCPConn, wakes <-chan uint32) {
	t.Helper()
	payload := []byte("native completion preserves every byte through peek, rearm and bounded discard")
	if _, err := peer.Write(payload); err != nil {
		t.Fatal(err)
	}
	waitQueuedTCPData(t, c) // prove the precondition before Arm, without consuming
	for range 3 {
		armImmediateTCP(t, c, wakes)
		var b [1]byte
		if n, err := c.TryPeek(b[:]); n != 1 || err != nil || b[0] != payload[0] {
			t.Fatalf("zero-byte receive/level rearm consumed data: n=%d byte=%d err=%v", n, b[0], err)
		}
	}
	var first [1]byte
	if n, err := c.TryDiscard(first[:]); n != 1 || err != nil || first[0] != payload[0] {
		t.Fatalf("bounded discard: %d %v", n, err)
	}
	received := []byte{first[0]}
	var buf [256]byte
	deadline := time.Now().Add(5 * time.Second)
	for len(received) < len(payload) {
		if time.Now().After(deadline) {
			t.Fatal("stream drain stalled")
		}
		n, err := c.TryRead(buf[:])
		if errors.Is(err, platform.ErrWouldBlock) {
			if err := c.watch.Arm(true, false); err != nil {
				t.Fatal(err)
			}
			waitCompletionWake(t, wakes)
			continue
		}
		if err != nil || n <= 0 {
			t.Fatalf("stream drain: %d %v", n, err)
		}
		received = append(received, buf[:n]...)
	}
	if !bytes.Equal(received, payload) {
		t.Fatalf("changed stream: %q", received)
	}
	if n, err := c.TryRead(buf[:]); n != 0 || !errors.Is(err, platform.ErrWouldBlock) {
		t.Fatalf("payload left duplicate bytes: %d %v", n, err)
	}

	// No peer write is allowed until pending is observed. This is a separate
	// real asynchronous receive, not a retry of the immediate-success case.
	pending, packets := c.pool.submitted.Load(), c.pool.completed.Load()
	if err := c.watch.Arm(true, false); err != nil {
		t.Fatal(err)
	}
	c.watch.mu.Lock()
	isPending := c.watch.pending
	c.watch.mu.Unlock()
	if !isPending || c.pool.submitted.Load() != pending+1 {
		t.Fatal("empty stream never entered the pending receive path")
	}
	if _, err := peer.Write([]byte{0xa5}); err != nil {
		t.Fatal(err)
	}
	thread := waitCompletionWake(t, wakes)
	if thread != c.pool.thread.Load() || c.pool.completed.Load() != packets+1 {
		t.Fatal("pending receive did not produce exactly one completion-port callback")
	}
	if n, err := c.TryRead(buf[:]); n != 1 || err != nil || buf[0] != 0xa5 {
		t.Fatalf("pending receive changed data: n=%d err=%v", n, err)
	}

	reply := []byte("exact native reply")
	deadline = time.Now().Add(5 * time.Second)
	for sent := 0; sent < len(reply); {
		if time.Now().After(deadline) {
			t.Fatal("native reply stalled")
		}
		n, err := c.TryWrite(reply[sent:])
		sent += n
		if errors.Is(err, platform.ErrWouldBlock) {
			if err := c.watch.Arm(false, true); err != nil {
				t.Fatal(err)
			}
			waitCompletionWake(t, wakes)
			continue
		}
		if err != nil || n <= 0 {
			t.Fatalf("native reply: %d %v", n, err)
		}
	}
	if _, err := io.ReadFull(peer, buf[:len(reply)]); err != nil || !bytes.Equal(buf[:len(reply)], reply) {
		t.Fatalf("peer received wrong reply: %q %v", buf[:len(reply)], err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if n, err := peer.Read(buf[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("peer lost client FIN: %d %v", n, err)
	}
	if err := c.watch.Arm(true, false); err != nil {
		t.Fatal(err)
	}
	if err := peer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	waitCompletionWake(t, wakes)
	if n, err := c.TryPeek(buf[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("client lost peer FIN: %d %v", n, err)
	}
	// FIN must remain level-triggered, irrespective of whether its provider
	// completes this particular submission synchronously or asynchronously.
	if err := c.watch.Arm(true, false); err != nil {
		t.Fatal(err)
	}
	waitCompletionWake(t, wakes)
	if n, err := c.TryRead(buf[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("FIN rearm changed EOF: %d %v", n, err)
	}
	c.watch.Detach()
	select {
	case thread := <-wakes:
		t.Fatalf("extra readiness callback on thread %d", thread)
	default:
	}
}

func TestTCPReadinessNativeNormalCompletions(t *testing.T) {
	hosted(t)
	for _, policy := range []tcpCompletionPolicy{
		{reason: "non-ifs-provider"},
		{reason: "provider-query-error", err: windows.WSAENETDOWN},
	} {
		t.Run(policy.reason, func(t *testing.T) {
			p := completionTestPool(t, policy)
			wakes := make(chan uint32, 16)
			c, peer := nativeTCPPair(t, p, "tcp4", completionThreadWake(wakes))
			stats := p.stats()
			if stats["allowSkipCompletionOnSuccess"] != false || stats["normalCompletionSockets"] != 1 || stats["skipSuccessSockets"] != 0 || stats["completionPolicy"] != policy.reason {
				t.Fatalf("incorrect normal-mode stats: %v", stats)
			}
			if (stats["providerQueryError"] != "") != (policy.err != nil) {
				t.Fatalf("lost query error: %v", stats)
			}
			exerciseTCPCompletionStream(t, c, peer, wakes)
			t.Logf("native ordinary-mode immediate packets, pending receive, exact source/bytes, rearm and bidirectional FIN: %v", p.stats())
		})
	}
}

func TestTCPReadinessNativeIFSOptimization(t *testing.T) {
	hosted(t)
	policy := queryTCPCompletionPolicy(windows.WSAEnumProtocols)
	if policy.err != nil {
		t.Fatalf("native WSAEnumProtocols query failed: %v", policy.err)
	}
	t.Logf("native provider catalog: arch=%s entries=%d policy=%s nonIFS=%s", runtime.GOARCH, policy.entries, policy.reason, policy.nonIFS)
	if !policy.allowSkip {
		if policy.reason != "non-ifs-provider" || policy.entries == 0 {
			t.Fatalf("unexpected native provider policy: %+v", policy)
		}
		t.Skipf("skip-success optimization needs an all-IFS host: %s", policy.nonIFS)
	}
	p := completionTestPool(t, policy)
	wakes := make(chan uint32, 16)
	c, peer := nativeTCPPair(t, p, "tcp4", completionThreadWake(wakes))
	stats := p.stats()
	if stats["skipSuccessSockets"] != 1 || stats["normalCompletionSockets"] != 0 || stats["allowSkipCompletionOnSuccess"] != true ||
		stats["nonIFSSocketProviders"] != uint64(0) || stats["socketProviderQueryErrors"] != uint64(0) {
		t.Fatalf("all-IFS catalog and socket provider did not enable skip-success: %v", stats)
	}
	exerciseTCPCompletionStream(t, c, peer, wakes)
	t.Log("all-IFS catalog and the socket's own IFS provider enabled skip-success; inline and pending paths preserved the stream")
}

// The catalog snapshot is taken once at startup. Each socket's own provider
// must still return IFS handles, or the socket keeps normal notifications.
func TestTCPReadinessSocketProviderGate(t *testing.T) {
	hosted(t)
	policy := queryTCPCompletionPolicy(windows.WSAEnumProtocols)
	if !policy.allowSkip {
		t.Skipf("the per-socket gate is reached only on an all-IFS host: %+v", policy)
	}
	for _, tc := range []struct {
		name  string
		query func(winhandle.Owner) (bool, error)
		stat  string
	}{
		{"non-IFS socket provider", func(socket winhandle.Owner) (bool, error) {
			// The real query still runs on the real socket; only its verdict is replaced.
			if _, err := socketProviderIFS(socket); err != nil {
				return false, err
			}
			return false, nil
		}, "nonIFSSocketProviders"},
		{"provider query error", func(winhandle.Owner) (bool, error) { return false, windows.WSAENOPROTOOPT }, "socketProviderQueryErrors"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := completionTestPool(t, policy)
			p.providerIFS = tc.query
			wakes := make(chan uint32, 16)
			c, peer := nativeTCPPair(t, p, "tcp4", completionThreadWake(wakes))
			stats := p.stats()
			if c.watch.skipSuccess || stats["skipSuccessSockets"] != 0 || stats["normalCompletionSockets"] != 1 || stats[tc.stat] != uint64(1) {
				t.Fatalf("socket provider gate did not keep normal notifications: %v", stats)
			}
			if tc.stat == "socketProviderQueryErrors" && stats["socketProviderQueryError"] != windows.WSAENOPROTOOPT.Error() {
				t.Fatalf("query failure lost its cause: %v", stats["socketProviderQueryError"])
			}
			exerciseTCPCompletionStream(t, c, peer, wakes)
		})
	}
}

func TestTCPReadinessUnexpectedCancelIsFatal(t *testing.T) {
	hosted(t)
	const childFlag = "NETSWITCH_TEST_TCP_CANCEL_FATAL"
	const retained = "TCP CANCEL FAILURE RETAINED PENDING REGISTRATION"
	switch os.Getenv(childFlag) {
	case "receive":
		p := completionTestPool(t, tcpCompletionPolicy{reason: "non-ifs-provider"})
		c, peer := nativeTCPPair(t, p, "tcp4", func() { panic("cancel-failure child unexpectedly woke") })
		p.cancel = func(windows.Handle, *windows.Overlapped) error { return windows.ERROR_ACCESS_DENIED }
		if err := c.watch.Arm(true, false); err != nil {
			t.Fatal(err)
		}
		c.watch.mu.Lock()
		pending := c.watch.pending
		c.watch.mu.Unlock()
		if !pending || p.submitted.Load() != 1 {
			t.Fatal("cancel-failure child never submitted its receive")
		}
		// A dedicated goroutine makes the panic process-fatal, outside the
		// testing runner's recover/cleanup. No peer close or fixture cleanup
		// can complete the pending receive before the retained-state check.
		go func() {
			defer func() {
				failure := recover()
				c.watch.mu.Lock()
				pending := c.watch.pending && c.watch.detached && errors.Is(c.watch.detachErr, windows.ERROR_ACCESS_DENIED)
				c.watch.mu.Unlock()
				p.mu.Lock()
				registered := p.watches[c.watch.key] == c.watch
				p.mu.Unlock()
				if failure != nil && pending && registered {
					fmt.Fprintln(os.Stderr, retained)
				}
				panic(failure)
			}()
			c.watch.Detach()
		}()
		time.Sleep(5 * time.Second)
		runtime.KeepAlive(peer)
		t.Fatal("unexpected cancellation error did not terminate the child")
	case "connect":
		p := completionTestPool(t, tcpCompletionPolicy{reason: "non-ifs-provider"})
		p.cancel = func(windows.Handle, *windows.Overlapped) error { return windows.ERROR_ACCESS_DENIED }
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		closed := unmapped(listener.Addr().(*net.TCPAddr).AddrPort())
		listener.Close()
		line := loopbackLine(t)
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			defer func() {
				failure := recover()
				p.mu.Lock()
				var watches []*socketWatch
				for _, w := range p.watches {
					watches = append(watches, w)
				}
				p.mu.Unlock()
				retainedPending := false
				if len(watches) == 1 {
					watches[0].mu.Lock()
					retainedPending = watches[0].pending && watches[0].connecting
					watches[0].mu.Unlock()
				}
				if failure != nil && retainedPending {
					fmt.Fprintln(os.Stderr, retained)
				}
				panic(failure)
			}()
			p.dial(ctx, line, loopbackSource(false), closed)
		}()
		for start := time.Now(); p.pendingConn.Load() == 0; time.Sleep(time.Millisecond) {
			if time.Since(start) > 5*time.Second {
				t.Fatal("cancel-failure child never had a pending ConnectEx")
			}
		}
		cancel()
		time.Sleep(5 * time.Second)
		t.Fatal("unexpected ConnectEx cancellation error did not terminate the child")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, child := range []struct{ mode, panic string }{
		{"receive", "panic: TCP readiness CancelIoEx"},
		{"connect", "panic: TCP ConnectEx CancelIoEx"},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		cmd := exec.CommandContext(ctx, executable, "-test.run=^TestTCPReadinessUnexpectedCancelIsFatal$", "-test.v", "-test.timeout=10s")
		cmd.Env = append(os.Environ(), childFlag+"="+child.mode)
		output, err := cmd.CombinedOutput()
		cancel()
		var exit *exec.ExitError
		if ctx.Err() != nil || !errors.As(err, &exit) || !bytes.Contains(output, []byte(retained)) || !bytes.Contains(output, []byte(child.panic)) {
			t.Fatalf("%s: unexpected cancel did not fail promptly with its live registration retained: err=%v context=%v\n%s", child.mode, err, ctx.Err(), output)
		}
	}
	t.Log("an unexpected CancelIoEx error for a receive or a ConnectEx terminated the child with its pending registration retained; no cleanup/free or indefinite wait")
}

func TestTCPReadinessNativeNormalCancelAndGenerations(t *testing.T) {
	hosted(t)
	p := completionTestPool(t, tcpCompletionPolicy{reason: "non-ifs-provider"})
	var wakes atomic.Uint32
	var previous *socketWatch
	seen := map[windows.Handle]bool{}
	reused := 0
	rounds := 0
	for round := range 32 {
		if !t.Run(fmt.Sprintf("generation-%02d", round), func(t *testing.T) {
			c, peer := nativeTCPPair(t, p, "tcp4", func() { wakes.Add(1) })
			h := c.handle.Handle("readiness test generation identity")
			if seen[h] {
				reused++
			}
			seen[h] = true
			if previous != nil {
				if c.watch.key <= previous.key {
					t.Fatal("completion registration key was reused")
				}
				previous.Detach() // must not cancel/close this generation
				if err := previous.Arm(true, true); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("ended generation rearmed: %v", err)
				}
			}
			pending := p.submitted.Load()
			if err := c.watch.Arm(true, false); err != nil {
				t.Fatal(err)
			}
			c.watch.mu.Lock()
			isPending := c.watch.pending
			c.watch.mu.Unlock()
			if !isPending || p.submitted.Load() != pending+1 {
				t.Fatal("cancellation precondition: no outstanding native receive")
			}
			packets := p.completed.Load()
			done := make(chan struct{})
			go func() { c.watch.Detach(); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Detach did not drain cancellation while both peers remained open")
			}
			if p.completed.Load() != packets+1 || p.stats()["sockets"] != 0 || wakes.Load() != 0 {
				t.Fatalf("cancellation lost its packet or invoked a detached callback: %v wakes=%d", p.stats(), wakes.Load())
			}
			if kind, err := windows.GetsockoptInt(c.handle.Handle("readiness test detached socket still live"), windows.SOL_SOCKET, 0x1008); err != nil || kind != windows.SOCK_STREAM { // SO_TYPE.
				t.Fatalf("Detach closed/recycled the native socket: type=%d %v", kind, err)
			}
			// The peer remains live and idle until after Detach and Close. Its
			// cleanup cannot manufacture the cancellation packet credited above.
			borrowed := c.handle
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			if winhandle.Enabled {
				func() {
					defer func() {
						if failure := recover(); failure == nil || !strings.Contains(fmt.Sprint(failure), "ended or replaced generation") {
							t.Fatalf("stale generation was not rejected before a syscall: %v", failure)
						}
					}()
					borrowed.Handle("readiness test stale generation negative control")
				}()
			}
			previous = c.watch
			rounds++
			runtime.KeepAlive(peer)
		}) {
			break
		}
	}
	t.Logf("%d independent pending cancellations; observed numeric socket-handle reuse=%d, handlecheck=%t", rounds, reused, winhandle.Enabled)
}

func TestTCPReadinessNormalQueuedSuccessDetach(t *testing.T) {
	hosted(t)
	p := completionTestPool(t, tcpCompletionPolicy{reason: "non-ifs-provider"})
	entered, release := make(chan struct{}), make(chan struct{})
	blocker, blockerPeer := nativeTCPPair(t, p, "tcp4", func() {
		close(entered)
		<-release
	})
	// Always release the completion worker before cleanup, including failures.
	var releaseOnce atomic.Bool
	resume := func() {
		if releaseOnce.CompareAndSwap(false, true) {
			close(release)
		}
	}
	defer resume()
	// Connect the second socket before pausing the worker: its ConnectEx
	// completes on that same worker.
	var wakes atomic.Uint32
	c, peer := nativeTCPPair(t, p, "tcp4", func() { wakes.Add(1) })
	if err := blocker.watch.Arm(true, false); err != nil {
		t.Fatal(err)
	}
	if _, err := blockerPeer.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("completion worker never entered the controlled callback")
	}
	// The real worker is paused in a different socket's callback. Immediate
	// success on this socket therefore leaves a real IOCP packet queued.
	if _, err := peer.Write([]byte{0x5a}); err != nil {
		t.Fatal(err)
	}
	waitQueuedTCPData(t, c)
	immediate, packets := p.immediate.Load(), p.completed.Load()
	if err := c.watch.Arm(true, false); err != nil {
		t.Fatal(err)
	}
	if p.immediate.Load() != immediate+1 || p.completed.Load() != packets {
		t.Fatal("fixture did not leave a synchronous-success packet queued")
	}
	canceled := make(chan error, 1)
	p.cancel = func(h windows.Handle, op *windows.Overlapped) error {
		err := windows.CancelIoEx(h, op)
		canceled <- err
		return err
	}
	detached := make(chan struct{})
	go func() { c.watch.Detach(); close(detached) }()
	select {
	case err := <-canceled:
		if !errors.Is(err, windows.ERROR_NOT_FOUND) {
			t.Fatalf("completed receive did not produce the real CancelIoEx not-found race: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Detach never attempted cancellation")
	}
	c.watch.mu.Lock()
	stillPending := c.watch.pending && c.watch.detached && c.watch.drained != nil
	c.watch.mu.Unlock()
	if !stillPending {
		t.Fatal("CancelIoEx not-found prematurely released the queued operation")
	}
	select {
	case <-detached:
		t.Fatal("Detach returned before consuming the already queued success packet")
	default:
	}
	resume()
	select {
	case <-detached:
	case <-time.After(5 * time.Second):
		t.Fatal("Detach failed to drain the queued success packet")
	}
	if p.completed.Load() != packets+1 || wakes.Load() != 0 {
		t.Fatal("queued success was lost or woke after detach")
	}
	var b [1]byte
	if n, err := c.TryRead(b[:]); n != 1 || err != nil || b[0] != 0x5a {
		t.Fatalf("detach/zero-byte receive changed queued data: %d %v", n, err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	blocker.watch.Detach()
	t.Log("real synchronous-success packet drained after CancelIoEx ERROR_NOT_FOUND, before native Close")
}
