//go:build linux

package linux

import (
	"hash/maphash"
	"slices"
	"sync"
)

const ownerIndexShards = 64
const ownerIndexEntries = 131072 / ownerIndexShards

type ownerIndex struct {
	mu      sync.Mutex
	inodes  map[uint32]inodeHolders
	waiters map[uint32]*inodeWaiter
}

func (o *Owners) indexFor(inode uint32) *ownerIndex {
	return &o.index[maphash.Comparable(o.indexSeed, inode)%ownerIndexShards]
}

// The common one-holder entry lives directly in the map. Publishing a batch
// of new sockets therefore needs no per-entry allocation under an index lock.
// Published slice prefixes are immutable; later holders only append to them.
type inodeHolders struct {
	first holder
	more  []holder
}

func (h inodeHolders) visit(accept func(holder) error) error {
	if h.first.pid == 0 {
		return nil
	}
	if err := accept(h.first); err != nil {
		return err
	}
	for _, v := range h.more {
		if err := accept(v); err != nil {
			return err
		}
	}
	return nil
}
func (h inodeHolders) count() int {
	if h.first.pid == 0 {
		return 0
	}
	return 1 + len(h.more)
}

type inodeWaiter struct {
	ready chan struct{}
	next  *inodeWaiter
}

func (o *Owners) indexed(inode uint32) inodeHolders {
	s := o.indexFor(inode)
	s.mu.Lock()
	h := s.inodes[inode]
	s.mu.Unlock()
	return h
}
func (o *Owners) subscribe(inode uint32) *inodeWaiter {
	w := &inodeWaiter{ready: make(chan struct{})}
	s := o.indexFor(inode)
	s.mu.Lock()
	w.next = s.waiters[inode]
	s.waiters[inode] = w
	s.mu.Unlock()
	return w
}
func (o *Owners) unsubscribe(inode uint32, w *inodeWaiter) {
	s := o.indexFor(inode)
	s.mu.Lock()
	defer s.mu.Unlock()
	var previous *inodeWaiter
	for current := s.waiters[inode]; current != nil; current = current.next {
		if current == w {
			if previous != nil {
				previous.next = current.next
			} else if current.next != nil {
				s.waiters[inode] = current.next
			} else {
				delete(s.waiters, inode)
			}
			return
		}
		previous = current
	}
}

func (o *Owners) publish(found map[uint32]holder) {
	if len(found) == 0 {
		return
	}
	for inode, h := range found {
		s := o.indexFor(inode)
		s.mu.Lock()
		old := s.inodes[inode]
		if old.first.pid == 0 && len(s.inodes) >= ownerIndexEntries {
			clear(s.inodes)
		}
		changed := false
		if old.first.pid == 0 {
			old.first = h
			changed = true
		} else if old.first != h && !slices.Contains(old.more, h) && len(old.more) < 7 {
			old.more = append(old.more, h)
			changed = true
		}
		if changed {
			s.inodes[inode] = old
		}
		// Wake only lookups for this inode, while the rest of the descriptor
		// batch is still being indexed. A 512-entry batch must not hold every
		// new connection's result until its last readlink completes.
		for w := s.waiters[inode]; w != nil; w = w.next {
			close(w.ready)
		}
		delete(s.waiters, inode)
		s.mu.Unlock()
	}
}
