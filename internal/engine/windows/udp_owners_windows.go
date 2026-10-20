//go:build windows

package winengine

import (
	"context"
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

type udpOwnerRefresh struct {
	done   chan struct{}
	result *udpOwnerSnapshot
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
		pending := o.udpRefreshes[family].Load()
		if pending == nil {
			pending = &udpOwnerRefresh{done: make(chan struct{})}
			if !o.udpRefreshes[family].CompareAndSwap(nil, pending) {
				continue
			}
			if s := o.udpSnapshots[family].Load(); freshUDPSnapshot(s, after, winclock.Now()) {
				pending.result = s
				o.udpRefreshes[family].Store(nil)
				close(pending.done)
				return s, s.err
			}
			go o.refreshUDP(pending, family)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-pending.done:
			s := pending.result
			if s.at <= after {
				continue
			}
			return s, s.err
		}
	}
}

func (o *Owners) refreshUDP(pending *udpOwnerRefresh, family int) {
	// The native read cannot be cancelled. One private deadline and one owner
	// per address family bound work without letting a cancelled lookup poison
	// every other caller. Reconciliation keeps its separate, fresh 1 s dump.
	ctx, cancel := winclock.System.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	s := &udpOwnerSnapshot{at: winclock.Now(), rows: make(map[netip.AddrPort][]socketOwner)}
	af := uint32(windows.AF_INET)
	if family == 1 {
		af = windows.AF_INET6
	}
	o.udpDumps.Add(1)
	started := winclock.Now()
	raw, err := readOwnerTableInto(ctx, udpTable, af, udpOwnerModule, &o.udpBuffers[family])
	o.udpReadNanos.Add(uint64(winclock.Since(started)))
	s.err = err
	if err == nil {
		started = winclock.Now()
		s.err = parseUDP(raw, family == 1, s.rows)
		o.udpIndexNanos.Add(uint64(winclock.Since(started)))
	}
	if s.err == nil {
		s.err = ctx.Err()
	}
	pending.result = s
	o.udpSnapshots[family].Store(s)
	o.udpRefreshes[family].Store(nil)
	close(pending.done)
}
