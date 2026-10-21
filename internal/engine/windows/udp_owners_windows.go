//go:build windows

package winengine

import (
	"context"
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/AyoubAchour/net-switch/internal/winclock"
	"golang.org/x/sys/windows"
)

type udpOwnerSnapshot struct {
	at   time.Duration
	rows map[netip.AddrPort][]socketOwner
	err  error
}

type udpOwnerRead = tableRead[*udpOwnerSnapshot]

func freshUDPSnapshot(snapshot *udpOwnerSnapshot, after, now time.Duration) bool {
	return snapshot != nil && snapshot.at > after && now >= snapshot.at && now-snapshot.at < 5*time.Millisecond
}

func (o *Owners) udpSnapshot(ctx context.Context, after time.Duration, family int) (*udpOwnerSnapshot, error) {
	run := func(r *udpOwnerRead) { o.refreshUDP(r, family) }
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if s := o.udpSnapshots[family].Load(); freshUDPSnapshot(s, after, winclock.Now()) {
			return s, s.err
		}
		pending := o.udpReads[family].join(after, run)
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

func (o *Owners) refreshUDP(pending *udpOwnerRead, family int) {
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
	// Each slot owns its scratch buffer; the reads may overlap.
	raw, err := readOwnerTableInto(ctx, udpTable, af, udpOwnerModule, &o.udpBuffers[family][pending.slot])
	read := winclock.Since(started)
	o.udpReadNanos.Add(uint64(read))
	measureStage(&o.udpReadHist, started)
	storeMax(&o.udpReadMaxUS, uint64(read.Microseconds()))
	s.err = err
	if err == nil {
		if len(raw) >= 4 {
			storeMax(&o.udpPeakRows, uint64(binary.LittleEndian.Uint32(raw)))
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
	o.udpReads[family].finish(pending, func(r *udpOwnerRead) { o.refreshUDP(r, family) })
}
