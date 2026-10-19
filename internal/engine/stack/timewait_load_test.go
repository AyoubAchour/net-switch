package stack_test

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func TestTimeWaitSameTupleUnderLoad(t *testing.T) {
	if os.Getenv("NETSWITCH_TIMEWAIT_GATE") != "1" {
		t.Skip("sustained load runs in the dedicated CI gate")
	}
	for _, cap := range []int{0, 1} {
		t.Run(fmt.Sprintf("cap_%d", cap), func(t *testing.T) {
			limits := flows.Defaults()
			limits.TimeWait, limits.Flows, limits.PerApp = cap, 1, 1
			p := newPeerOptions(t, false, limits, ns.DefaultOptions())
			const n = 2000
			start := time.Now()
			for i := range n {
				if i%100 == 0 {
					time.Sleep(time.Until(start.Add(time.Duration(i) * time.Millisecond)))
				}
				p.open(1000) // The same port and overlapping sequence space every time.
				p.upload([]byte("reuse"))
				p.closeActive()
			}
			elapsed := time.Since(start)
			if elapsed > 3*time.Second {
				t.Fatalf("could not sustain 1000 same-tuple reuses/s: %s", elapsed)
			}
			deadline := time.Now().Add(time.Second)
			for p.table.Stats().Flows != 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			wantSkipped := uint64(0)
			if cap == 0 {
				wantSkipped = n
			}
			if g := p.table.Stats(); g.Admitted != n || g.Flows != 0 || g.TimeWait != cap || g.TimeWaitSkipped != wantSkipped || g.Rejected != 0 || p.dials.Load() != n {
				t.Fatal("same-tuple load lost or duplicated a connection", g)
			}
			if p.stack.Stats().TCP.ResetsSent.Value() != 0 || p.forward.Rejected.Load() != 0 || len(p.stack.RegisteredEndpoints()) != cap {
				t.Fatal("same-tuple load reset, rejected or retained an extra endpoint")
			}
			if got := p.table.Totals().Apps["peer"].Up; got != 5*n {
				t.Fatalf("payload accounting = %d, want %d", got, 5*n)
			}
			t.Logf("%d/%d same-tuple connections in %s; cap=%d skipped=%d; RST=0; payloads hash-checked", n, n, elapsed, cap, wantSkipped)
		})
	}
}

// Run once in the CI gate, outside the race suite. It exercises real wire
// handshakes, relay payloads and graceful closes using the unmodified defaults.
func TestTimeWaitThousandPerSecondSuccess(t *testing.T) {
	if os.Getenv("NETSWITCH_TIMEWAIT_GATE") != "1" {
		t.Skip("sustained load runs in the dedicated CI gate")
	}
	limits := flows.Defaults()
	p := newPeer(t, false)
	n := max(10_000, limits.TimeWait+1024)
	start := time.Now()
	for i := range n {
		// Offer 100 connections every 100 ms, for at least ten seconds and
		// long enough to fill TIME_WAIT and exceed a single app's flow quota.
		if i%100 == 0 {
			time.Sleep(time.Until(start.Add(time.Duration(i) * time.Millisecond)))
		}
		p.port = uint16(20000 + i)
		p.open(1000)
		p.upload([]byte("load"))
		p.closeActive()
		if g := p.table.Stats(); g.TimeWait > limits.TimeWait || g.Rejected != 0 {
			t.Fatalf("connection %d: %+v", i, g)
		}
	}
	elapsed := time.Since(start)
	if elapsed > time.Duration(n)*time.Millisecond+time.Second {
		t.Fatalf("could not sustain 1000 connections/s: %d in %s", n, elapsed)
	}
	// Wait only for the final close's accounting, not endpoint expiration.
	deadline := time.Now().Add(time.Second)
	for p.table.Stats().Flows != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	g := p.table.Stats()
	if g.Admitted != uint64(n) || p.dials.Load() != uint64(n) || g.Flows != 0 || g.TimeWait != limits.TimeWait || g.TimeWaitSkipped != uint64(n-limits.TimeWait) || g.Rejected != 0 {
		t.Fatal(g)
	}
	if endpoints := len(p.stack.RegisteredEndpoints()); endpoints != limits.TimeWait {
		t.Fatalf("retained %d actual endpoints, cap %d", endpoints, limits.TimeWait)
	}
	if page, err := p.table.Page(""); err != nil || len(page.Flows) != 0 {
		t.Fatal("closed connections appeared live", page, err)
	}
	if got := p.table.Totals().Apps["peer"].Up; got != uint64(4*n) {
		t.Fatalf("relay accounting = %d, want %d", got, 4*n)
	}
	if resets := p.stack.Stats().TCP.ResetsSent.Value(); resets != 0 || p.forward.Rejected.Load() != 0 {
		t.Fatalf("resets=%d rejected=%d", resets, p.forward.Rejected.Load())
	}
	if h := p.read(5 * time.Millisecond); h != nil {
		t.Fatalf("unexpected trailing packet: %v", h.Flags())
	}
	t.Logf("%d/%d successful connections in %s; TIME_WAIT=%d cap=%d skipped=%d; RST=0; payloads hash-checked", n, n, elapsed, g.TimeWait, limits.TimeWait, g.TimeWaitSkipped)
}

// The profile includes the endpoint's retained graph, not unsafe.Sizeof alone.
// Run in a separate process with full allocation sampling; CI keeps the pprof.
func TestTimeWaitEndpointMemory(t *testing.T) {
	profile := os.Getenv("NETSWITCH_TIMEWAIT_PROFILE")
	if profile == "" {
		t.Skip("heap measurement runs separately in CI")
	}
	previous := runtime.MemProfileRate
	runtime.MemProfileRate = 1
	defer func() { runtime.MemProfileRate = previous }()
	p := newPeer(t, false)
	// Warm all paths before measuring. That endpoint remains in both samples.
	p.open(1000)
	p.upload([]byte("warm"))
	p.closeActive()
	settle := func() {
		time.Sleep(50 * time.Millisecond)
		runtime.GC()
		runtime.GC() // Heap profiles can lag one collection.
	}
	settle()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	baseProfile := retainedTCPBytes()
	const n = 512
	for i := range n {
		p.port = uint16(41000 + i)
		p.open(1000)
		p.upload([]byte("heap"))
		p.closeActive()
	}
	settle()
	for _, endpoint := range p.stack.RegisteredEndpoints() {
		ep := endpoint.(*tcp.Endpoint)
		if tcp.EndpointState(ep.State()) != tcp.StateTimeWait {
			t.Fatal("profile contains a live endpoint")
		}
		// gVisor can subtract the FIN's sequence byte from SndBufUsed,
		// leaving -1 after all payload is acknowledged.
		if rx, tx := ep.BufferUsage(); rx != 0 || tx > 0 {
			t.Fatalf("profile before buffer release: rx=%d tx=%d", rx, tx)
		}
	}
	if g := p.table.Stats(); g.TimeWait != n+1 || g.Flows != 0 || g.TCPBytes != 0 {
		t.Fatal("profile is not settled", g)
	}
	runtime.ReadMemStats(&after)
	heapPerEndpoint := (int64(after.HeapAlloc) - int64(before.HeapAlloc)) / n
	tcpPerEndpoint := (retainedTCPBytes() - baseProfile) / n
	f, err := os.Create(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := pprof.WriteHeapProfile(f); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	t.Logf("TIME_WAIT memory: %d endpoints, heap delta %d bytes/endpoint (includes engine bookkeeping); TCP allocation stacks %d bytes/endpoint; no queued payload; profile=%s", n, heapPerEndpoint, tcpPerEndpoint, profile)
	if heapPerEndpoint <= 0 || tcpPerEndpoint <= 0 {
		t.Fatal("invalid heap measurement")
	}
	if heapPerEndpoint*int64(flows.Defaults().TimeWait) > 32<<20 {
		t.Fatal("default TIME_WAIT cap exceeds 32 MiB at measured endpoint size")
	}
}

func retainedTCPBytes() int64 {
	n, _ := runtime.MemProfile(nil, false)
	for {
		records := make([]runtime.MemProfileRecord, n+32)
		var ok bool
		n, ok = runtime.MemProfile(records, false)
		if !ok {
			continue
		}
		var bytes int64
		for _, r := range records[:n] {
			frames := runtime.CallersFrames(r.Stack())
			for {
				frame, more := frames.Next()
				if strings.Contains(frame.Function, "gvisor.dev/gvisor/pkg/tcpip/transport/tcp.") {
					bytes += r.InUseBytes()
					break
				}
				if !more {
					break
				}
			}
		}
		return bytes
	}
}
