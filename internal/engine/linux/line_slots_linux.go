package linux

import (
	"errors"
	"sync/atomic"
)

// A tombstone prevents an old published binding from acquiring a socket after
// the route writer retires its slot. Dials never wait for netlink or fsync.
type lineLease struct{ users atomic.Int64 }

func (l *lineLease) hold() bool {
	if l == nil {
		return true
	} // hand-built platform fixtures
	for n := l.users.Load(); n >= 0; n = l.users.Load() {
		if l.users.CompareAndSwap(n, n+1) {
			return true
		}
	}
	return false
}
func (l *lineLease) release() {
	if l != nil {
		l.users.Add(-1)
	}
}
func (l *lineLease) retire() bool { return l == nil || l.users.CompareAndSwap(0, -1) }

func (p *Platform) SetLineUse(used func(string) bool) { p.lineUsed = used }

// Called under routeMu. A policy reference protects the prepare/apply gap;
// socket pins also cover probes, echo, pending dials and delayed closes.
func (p *Platform) retireLines(wanted map[string]bool) bool {
	changed := false
	for id, line := range p.lines {
		if wanted[id] || (p.lineUsed != nil && p.lineUsed(id)) {
			continue
		}
		if line.lease.retire() {
			delete(p.lines, id)
			changed = true
			p.slotsDirty = true
		}
	}
	return changed
}

func freeLineSlot(lines map[string]lineState) int {
	var used [256]bool
	for _, line := range lines {
		if line.N > 0 && line.N < len(used) {
			used[line.N] = true
		}
	}
	for n := 1; n < len(used); n++ {
		if !used[n] {
			return n
		}
	}
	return 0
}

func (p *Platform) acquireBinding(id string, v6 bool) (lineState, func(), error) {
	l, err := p.binding(id, v6)
	if err != nil {
		return l, nil, err
	}
	if !l.lease.hold() {
		return l, nil, errors.New("line binding retired")
	}
	return l, l.lease.release, nil
}
