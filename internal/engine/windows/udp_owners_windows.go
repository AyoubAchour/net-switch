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
	rows udpRows
	err  error
}

// udpRow is one local endpoint's first owner and how many rows share it.
// More than one is ambiguous; only the count matters beyond the first.
type udpRow struct {
	owner socketOwner
	count uint32
}

// udpRows indexes a UDP owner table by its exact local address and port, in
// fixed-size keys: one map entry per endpoint and no per-row allocation. At
// about 16,000 rows per read this is rebuilt for every lookup batch.
type udpRows struct {
	v4 map[[6]byte]udpRow
	v6 map[[18]byte]udpRow
}

func newUDPRows(v4, v6 int) udpRows {
	return udpRows{v4: make(map[[6]byte]udpRow, v4), v6: make(map[[18]byte]udpRow, v6)}
}

func (r *udpRows) add(key netip.AddrPort, owner socketOwner) {
	if key.Addr().Is4() {
		k := udp4Key(key)
		row := r.v4[k]
		if row.count == 0 {
			row.owner = owner
		}
		row.count++
		r.v4[k] = row
		return
	}
	k := udp6Key(key)
	row := r.v6[k]
	if row.count == 0 {
		row.owner = owner
	}
	row.count++
	r.v6[k] = row
}

func (r udpRows) find(key netip.AddrPort) udpRow {
	if key.Addr().Is4() {
		return r.v4[udp4Key(key)]
	}
	return r.v6[udp6Key(key)]
}

func udp4Key(key netip.AddrPort) (k [6]byte) {
	a := key.Addr().As4()
	copy(k[:], a[:])
	binary.BigEndian.PutUint16(k[4:], key.Port())
	return k
}

func udp6Key(key netip.AddrPort) (k [18]byte) {
	a := key.Addr().As16()
	copy(k[:], a[:])
	binary.BigEndian.PutUint16(k[16:], key.Port())
	return k
}

type udpOwnerRead = tableRead[*udpOwnerSnapshot]

func freshUDPSnapshot(snapshot *udpOwnerSnapshot, after, now time.Duration) bool {
	return snapshot != nil && snapshot.at > after && now >= snapshot.at && now-snapshot.at < 5*time.Millisecond
}

func (o *Owners) udpSnapshot(ctx context.Context, after time.Duration, family int) (*udpOwnerSnapshot, bool, error) {
	run := func(r *udpOwnerRead) { o.refreshUDP(r, family) }
	normal, cancel := winclock.System.WithTimeout(ctx, max(0, ownerLookupBound-winclock.Since(after)))
	defer cancel()
	bound := normal.Done()
	held := false
	for {
		if err := ctx.Err(); err != nil {
			return nil, held, err
		}
		if s := o.udpSnapshots[family].Load(); freshUDPSnapshot(s, after, winclock.Now()) {
			return s, held, s.err
		}
		pending := o.udpReads[family].join(after, run)
		waited := winclock.Now()
	wait:
		for {
			select {
			case <-ctx.Done():
				measureStage(&o.udpWaitHist, waited)
				return nil, held, ctx.Err()
			case <-bound:
				// join already selected the single shared read newer than this
				// setup. Keep waiting for it; never start per-waiter retries.
				o.udpHolds.Add(1)
				held, bound = true, nil
			case <-pending.done:
				measureStage(&o.udpWaitHist, waited)
				if s := pending.result; s.at > after {
					return s, held, s.err
				}
				break wait
			}
		}
	}
}

func (o *Owners) refreshUDP(pending *udpOwnerRead, family int) {
	// The native read cannot be cancelled. One private deadline per read
	// bounds work without letting a cancelled lookup poison every other
	// caller. Reconciliation keeps its separate, fresh 1 s dump.
	ctx, cancel := winclock.System.WithTimeout(context.Background(), ownerOverloadHold)
	defer cancel()
	s := &udpOwnerSnapshot{at: pending.at}
	af := uint32(windows.AF_INET)
	if family == 1 {
		af = windows.AF_INET6
	}
	o.udpDumps.Add(1)
	started := winclock.Now()
	// From the slot's start (pending.at) to a published snapshot, including
	// any wait for a goroutine to run this read.
	defer measureStage(&o.udpRefreshHist, pending.at)
	// Each slot owns its scratch buffer; the reads may overlap.
	var raw []byte
	var err error
	if o.readUDP != nil {
		raw, err = o.readUDP(ctx, af, &o.udpBuffers[family][pending.slot])
	} else {
		raw, err = readOwnerTableInto(ctx, udpTable, af, udpOwnerModule, &o.udpBuffers[family][pending.slot])
	}
	read := winclock.Since(started)
	o.udpReadNanos.Add(uint64(read))
	measureStage(&o.udpReadHist, started)
	storeMax(&o.udpReadMaxUS, uint64(read.Microseconds()))
	s.err = err
	if err == nil {
		rows := 0
		if len(raw) >= 4 {
			rows = int(binary.LittleEndian.Uint32(raw))
			storeMax(&o.udpPeakRows, uint64(rows))
		}
		started = winclock.Now()
		if family == 1 {
			s.rows = newUDPRows(0, rows)
		} else {
			s.rows = newUDPRows(rows, 0)
		}
		s.err = parseUDP(raw, family == 1, &s.rows)
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
