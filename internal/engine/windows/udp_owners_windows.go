//go:build windows

package winengine

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"github.com/AyoubAchour/net-switch/internal/winclock"
	"golang.org/x/sys/windows"
)

type udpOwnerSnapshot struct {
	at   time.Duration
	rows map[netip.AddrPort][]socketOwner
	err  error
}

// udpOwnerParallelReads is how many native UDP table reads one address family
// may have in flight. Every lookup needs a read that started after it began.
// With one read at a time, a lookup arriving mid-read waited for that read and
// then a whole second one: about two reads, which crossed the 50 ms lookup
// bound near the UDP cap on x64 (run 39564185852: 30 lookups timed out at
// about 15,000 system UDP sockets, below the floor). With two staggered reads
// a lookup joins a read that started after it, or starts one at once, or
// waits for the first free slot.
const udpOwnerParallelReads = 2

type udpOwnerRefresh struct {
	at     time.Duration // set when the read is started; every waiter began before it
	slot   int
	done   chan struct{}
	result *udpOwnerSnapshot
}

// udpOwnerReads schedules one address family's native reads.
type udpOwnerReads struct {
	mu      sync.Mutex
	running [udpOwnerParallelReads]*udpOwnerRefresh
	queued  *udpOwnerRefresh
	peak    int
}

func freshUDPSnapshot(snapshot *udpOwnerSnapshot, after, now time.Duration) bool {
	return snapshot != nil && snapshot.at > after && now >= snapshot.at && now-snapshot.at < 5*time.Millisecond
}

func (o *Owners) udpSnapshot(ctx context.Context, after time.Duration, family int) (*udpOwnerSnapshot, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if s := o.udpSnapshots[family].Load(); freshUDPSnapshot(s, after, winclock.Now()) {
			return s, s.err
		}
		pending := o.joinUDPRead(family, after)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-pending.done:
			if s := pending.result; s.at > after {
				return s, s.err
			}
		}
	}
}

// joinUDPRead returns a read that starts, or started, after `after`.
func (o *Owners) joinUDPRead(family int, after time.Duration) *udpOwnerRefresh {
	q := &o.udpReads[family]
	q.mu.Lock()
	defer q.mu.Unlock()
	var newest *udpOwnerRefresh
	for _, r := range q.running {
		if r != nil && r.at > after && (newest == nil || r.at > newest.at) {
			newest = r
		}
	}
	if newest != nil {
		return newest
	}
	if q.queued != nil {
		return q.queued // it starts later than this call, so it covers it
	}
	r := &udpOwnerRefresh{done: make(chan struct{})}
	for slot, running := range q.running {
		if running == nil {
			o.startUDPRead(q, r, family, slot)
			return r
		}
	}
	q.queued = r
	return r
}

// startUDPRead runs under q.mu.
func (o *Owners) startUDPRead(q *udpOwnerReads, r *udpOwnerRefresh, family, slot int) {
	r.slot, r.at = slot, winclock.Now()
	q.running[slot] = r
	inFlight := 0
	for _, running := range q.running {
		if running != nil {
			inFlight++
		}
	}
	q.peak = max(q.peak, inFlight)
	go o.refreshUDP(r, family)
}

func (o *Owners) refreshUDP(pending *udpOwnerRefresh, family int) {
	// The native read cannot be cancelled. One private deadline per read
	// bounds work without letting a cancelled lookup poison every other
	// caller. Reconciliation keeps its separate, fresh 1 s dump.
	ctx, cancel := winclock.System.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	s := &udpOwnerSnapshot{at: pending.at, rows: make(map[netip.AddrPort][]socketOwner)}
	af := uint32(windows.AF_INET)
	if family == 1 {
		af = windows.AF_INET6
	}
	o.udpDumps.Add(1)
	started := winclock.Now()
	// Each slot owns its scratch buffer; the two reads may overlap.
	raw, err := readOwnerTableInto(ctx, udpTable, af, udpOwnerModule, &o.udpBuffers[family][pending.slot])
	read := winclock.Since(started)
	o.udpReadNanos.Add(uint64(read))
	measureStage(&o.udpReadHist, started)
	for old := o.udpReadMaxUS.Load(); uint64(read.Microseconds()) > old; old = o.udpReadMaxUS.Load() {
		if o.udpReadMaxUS.CompareAndSwap(old, uint64(read.Microseconds())) {
			break
		}
	}
	s.err = err
	if err == nil {
		if len(raw) >= 4 {
			rows := uint64(binary.LittleEndian.Uint32(raw))
			for old := o.udpPeakRows.Load(); rows > old; old = o.udpPeakRows.Load() {
				if o.udpPeakRows.CompareAndSwap(old, rows) {
					break
				}
			}
		}
		started = winclock.Now()
		s.err = parseUDP(raw, family == 1, s.rows)
		o.udpIndexNanos.Add(uint64(winclock.Since(started)))
	}
	if s.err == nil {
		s.err = ctx.Err()
	}
	pending.result = s
	// Reads may finish out of order; keep the newest-started snapshot.
	for current := o.udpSnapshots[family].Load(); current == nil || current.at < s.at; current = o.udpSnapshots[family].Load() {
		if o.udpSnapshots[family].CompareAndSwap(current, s) {
			break
		}
	}
	q := &o.udpReads[family]
	q.mu.Lock()
	q.running[pending.slot] = nil
	if next := q.queued; next != nil {
		q.queued = nil
		o.startUDPRead(q, next, family, pending.slot)
	}
	q.mu.Unlock()
	close(pending.done)
}

func (o *Owners) udpParallelPeak() int {
	peak := 0
	for family := range o.udpReads {
		q := &o.udpReads[family]
		q.mu.Lock()
		peak = max(peak, q.peak)
		q.mu.Unlock()
	}
	return peak
}
