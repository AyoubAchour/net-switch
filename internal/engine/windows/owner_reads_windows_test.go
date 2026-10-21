//go:build windows

package winengine

import (
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/winclock"
)

// TestTableReadsCoverEveryWaiter checks the scheduler's rules without native
// reads: at most ownerParallelReads in flight, every returned read starts
// after its caller's instant, waiters share reads, and a queued read starts
// in the first slot that frees.
func TestTableReadsCoverEveryWaiter(t *testing.T) {
	var q tableReads[int]
	started := make(chan *tableRead[int], 8)
	run := func(r *tableRead[int]) { started <- r }
	next := func() *tableRead[int] {
		t.Helper()
		select {
		case r := <-started:
			return r
		case <-time.After(5 * time.Second):
			t.Fatal("read did not start")
			return nil
		}
	}
	instant := func() time.Duration {
		// QPC can return equal values for back-to-back calls; a lookup's
		// instant must be strictly before any read it is given.
		now := winclock.Now()
		for winclock.Now() == now {
		}
		return now
	}

	a := instant()
	first := q.join(a, run)
	if r := next(); r != first || r.slot != 0 || r.at <= a {
		t.Fatalf("first read: slot=%d at=%s after=%s", r.slot, r.at, a)
	}
	if q.join(a, run) != first {
		t.Fatal("a caller covered by the running read started another")
	}

	b := instant()
	second := q.join(b, run)
	if r := next(); r != second || r.slot != 1 || r.at <= b {
		t.Fatalf("second read: slot=%d at=%s after=%s", r.slot, r.at, b)
	}

	c := instant()
	queued := q.join(c, run)
	if queued == first || queued == second || q.join(instant(), run) != queued {
		t.Fatal("callers after both running reads did not share one queued read")
	}
	select {
	case r := <-started:
		t.Fatalf("a third read started with both slots busy: slot=%d", r.slot)
	default:
	}
	if q.peakInFlight() != ownerParallelReads {
		t.Fatalf("peak in flight = %d, want %d", q.peakInFlight(), ownerParallelReads)
	}

	first.result = 1
	q.finish(first, run)
	select {
	case <-first.done:
	default:
		t.Fatal("finish did not wake the first read's waiters")
	}
	if r := next(); r != queued || r.slot != 0 || r.at <= c {
		t.Fatalf("queued read: slot=%d at=%s after=%s", r.slot, r.at, c)
	}
	second.result, queued.result = 2, 3
	q.finish(second, run)
	q.finish(queued, run)
	if q.peakInFlight() > ownerParallelReads {
		t.Fatalf("peak in flight %d exceeds %d", q.peakInFlight(), ownerParallelReads)
	}
}
