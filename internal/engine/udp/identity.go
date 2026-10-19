package udp

import (
	"context"
	"net/netip"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

func same(a, b platform.Owner) bool {
	return a.Generation != "" && a.Generation == b.Generation && a.PID == b.PID && a.StartTime == b.StartTime && a.AppID == b.AppID
}

func (n *NAT) sessions() []*session {
	var out []*session
	for i := range n.table {
		b := &n.table[i]
		b.Lock()
		for _, s := range b.m {
			out = append(out, s)
		}
		b.Unlock()
	}
	return out
}

// Reconcile serializes dumps. A result is only as fresh as the dump's start,
// so a stalled snapshot cannot give an old identity two more seconds of life.
func (n *NAT) Reconcile(ctx context.Context) {
	n.reconcileMu.Lock()
	defer n.reconcileMu.Unlock()
	started := n.now()
	sessions := n.sessions()
	keys := make([]netip.AddrPort, 0, len(sessions))
	active := make([]*session, 0, len(sessions))
	for _, s := range sessions {
		s.mu.Lock()
		ready := s.active && !s.closed
		idle := started.Sub(s.last) >= IdleTimeout
		s.mu.Unlock()
		if idle {
			s.close()
			continue
		}
		if ready {
			keys = append(keys, s.source)
			active = append(active, s)
		}
	}
	if len(keys) == 0 {
		return
	}
	if n.identities == nil {
		n.IdentityErrors.Add(1)
		return
	}
	owners, err := n.identities.Snapshot(ctx, keys)
	if err != nil {
		n.IdentityErrors.Add(1)
		return
	}
	for _, s := range active {
		s.mu.Lock()
		owner, ok := owners[s.source]
		valid := ok && same(s.owner, owner)
		if valid && !s.closed {
			s.validated = started
		}
		s.mu.Unlock()
		if !valid {
			s.close()
		}
	}
}

// Destroy matches the generation, never just the reused port. A dropped event
// or listener restart calls RefreshNow; the periodic dump remains the bound.
func (n *NAT) Destroy(source netip.AddrPort, generation string) {
	b := n.bucket(source)
	b.Lock()
	s := b.m[source]
	b.Unlock()
	if s == nil {
		return
	}
	s.mu.Lock()
	match := s.owner.Generation == generation && generation != ""
	s.mu.Unlock()
	if match {
		s.close()
	}
}
func (n *NAT) RefreshNow() {
	select {
	case n.refresh <- struct{}{}:
	default:
	}
}
func (n *NAT) ObserveICMP(raw []byte) bool {
	source, ok := packet.AppUnreachable(raw)
	if !ok {
		return false
	}
	b := n.bucket(source)
	b.Lock()
	s := b.m[source]
	b.Unlock()
	if s != nil {
		s.close()
	}
	return true
}

func (n *NAT) maintenance() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-tick.C:
		case <-n.refresh:
		}
		ctx, cancel := context.WithTimeout(n.ctx, time.Second)
		n.Reconcile(ctx)
		cancel()
	}
}

func (n *NAT) Close() {
	if n.closed.Swap(true) {
		return
	}
	n.cancel()
	for _, s := range n.sessions() {
		s.close()
	}
	n.wg.Wait()
}
