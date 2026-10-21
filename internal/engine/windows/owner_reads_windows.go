//go:build windows

package winengine

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/AyoubAchour/net-switch/internal/winclock"
)

// ownerParallelReads is how many native owner-table reads one table family
// (TCP or UDP, IPv4 or IPv6) may have in flight. Every lookup needs a read
// that started after a given instant. With one read at a time, a lookup that
// arrived mid-read waited for that read and then a whole second one. Near the
// Windows caps (about 15,000 UDP and 14,000 TCP rows on x64, run 39564185852
// and the mixed run on 853e295) a read took 5-25 ms, and lookups waiting for
// two reads crossed the 50 ms bound: UDP sessions were refused, and TCP SYNs
// became unknown-owner flows on the main line. With two staggered reads a
// lookup joins a read that started after its instant, starts one at once,
// or joins the single queued read that starts when a slot frees.
const ownerParallelReads = 2

// tableRead is one native table read. Every waiter's instant precedes at,
// which is set when the read is started.
type tableRead[S any] struct {
	at     time.Duration
	slot   int
	done   chan struct{}
	result S
}

// tableReads schedules one table family's reads. run executes a started read
// on its own goroutine and must end by calling finish.
type tableReads[S any] struct {
	mu      sync.Mutex
	running [ownerParallelReads]*tableRead[S]
	queued  *tableRead[S]
	peak    int
	// typical is a moving average of how long one read takes, from start
	// to finish. Reads start at least typical/ownerParallelReads apart.
	// Started back to back, two reads finish together and the queued one
	// still waits for both (seen on x64 at d99a743: lookups waited about
	// two reads with two slots busy).
	typical time.Duration
}

// join returns a read that starts, or started, after `after`.
func (q *tableReads[S]) join(after time.Duration, run func(*tableRead[S])) *tableRead[S] {
	q.mu.Lock()
	defer q.mu.Unlock()
	var newest, latest *tableRead[S]
	for _, r := range q.running {
		if r == nil {
			continue
		}
		if r.at > after && (newest == nil || r.at > newest.at) {
			newest = r
		}
		if latest == nil || r.at > latest.at {
			latest = r
		}
	}
	if newest != nil {
		return newest
	}
	if q.queued != nil {
		return q.queued // it starts later than this call, so it covers it
	}
	r := &tableRead[S]{done: make(chan struct{})}
	free := q.free()
	if free < 0 {
		q.queued = r // starts in the first slot that frees
		return r
	}
	gap := q.typical / ownerParallelReads
	if latest == nil || gap <= 0 {
		q.start(r, free, run)
		return r
	}
	if wait := latest.at + gap - winclock.Now(); wait > 0 {
		// Too soon after the latest start: queue it for the stagger point,
		// or for an earlier free slot, whichever comes first.
		q.queued = r
		time.AfterFunc(wait, func() {
			q.mu.Lock()
			defer q.mu.Unlock()
			if q.queued == r {
				if slot := q.free(); slot >= 0 {
					q.queued = nil
					q.start(r, slot, run)
				}
			}
		})
		return r
	}
	q.start(r, free, run)
	return r
}

// since returns the newest running read that started at or after instant,
// else the queued read, which starts later than any current waiter, else nil.
func (q *tableReads[S]) since(instant time.Duration) *tableRead[S] {
	q.mu.Lock()
	defer q.mu.Unlock()
	var newest *tableRead[S]
	for _, r := range q.running {
		if r != nil && r.at >= instant && (newest == nil || r.at > newest.at) {
			newest = r
		}
	}
	if newest != nil {
		return newest
	}
	return q.queued
}

// free returns a free slot or -1. It runs under q.mu.
func (q *tableReads[S]) free() int {
	for slot, running := range q.running {
		if running == nil {
			return slot
		}
	}
	return -1
}

// start runs under q.mu.
func (q *tableReads[S]) start(r *tableRead[S], slot int, run func(*tableRead[S])) {
	r.slot, r.at = slot, winclock.Now()
	q.running[slot] = r
	inFlight := 0
	for _, running := range q.running {
		if running != nil {
			inFlight++
		}
	}
	q.peak = max(q.peak, inFlight)
	go run(r)
}

// finish frees r's slot, starts the queued read in it if there is one, and
// then wakes r's waiters. r.result must already be set.
func (q *tableReads[S]) finish(r *tableRead[S], run func(*tableRead[S])) {
	q.mu.Lock()
	if took := winclock.Now() - r.at; q.typical == 0 {
		q.typical = took
	} else {
		q.typical += (took - q.typical) / 8
	}
	q.running[r.slot] = nil
	if next := q.queued; next != nil {
		q.queued = nil
		q.start(next, r.slot, run)
	}
	q.mu.Unlock()
	close(r.done)
}

// storeMax raises v to n if n is larger.
func storeMax(v *atomic.Uint64, n uint64) {
	for old := v.Load(); n > old; old = v.Load() {
		if v.CompareAndSwap(old, n) {
			return
		}
	}
}

func (q *tableReads[S]) peakInFlight() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.peak
}
