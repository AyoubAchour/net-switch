//go:build linux

package linux

import (
	"hash/maphash"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

const ownerIndexShards = 64
const ownerIndexEntries = 131072 / ownerIndexShards

type ownerIndex struct {
	mu      sync.Mutex
	inodes  map[uint32]inodeHolders
	waiters map[uint32]*inodeWaiter
	cookies map[uint64]cachedHolders
}

func (o *Owners) cookieIndex(cookie uint64) *ownerIndex {
	return &o.index[maphash.Comparable(o.indexSeed, cookie)%ownerIndexShards]
}

func (o *Owners) cachedHolders(cookie uint64) []holder {
	s := o.cookieIndex(cookie)
	s.mu.Lock()
	h := s.cookies[cookie].holders
	s.mu.Unlock()
	return h
}

func (o *Owners) cacheHolders(cookie uint64, holders []holder) {
	s := o.cookieIndex(cookie)
	s.mu.Lock()
	if s.cookies == nil {
		s.cookies = make(map[uint64]cachedHolders, 16)
	}
	s.cookies[cookie] = cachedHolders{holders, time.Now()}
	s.mu.Unlock()
}

func (o *Owners) forgetCookie(cookie uint64) {
	s := o.cookieIndex(cookie)
	s.mu.Lock()
	delete(s.cookies, cookie)
	s.mu.Unlock()
}

func (o *Owners) pruneCookies(live map[uint64]bool, started time.Time) {
	for i := range o.index {
		s := &o.index[i]
		s.mu.Lock()
		for cookie, cached := range s.cookies {
			if !live[cookie] && cached.observed.Before(started) {
				delete(s.cookies, cookie)
			}
		}
		s.mu.Unlock()
	}
}

func (o *Owners) indexFor(inode uint32) *ownerIndex {
	return &o.index[maphash.Comparable(o.indexSeed, inode)%ownerIndexShards]
}

type pidHints struct {
	values [32]uint32
	count  int
}

type recentOwners struct{ hints atomic.Pointer[pidHints] }

// The map lock only creates a UID slot. Matching another flow never needs
// its write side, so a burst of hint updates cannot stop lookup readers.
func (o *Owners) recentFor(uid uint32) *recentOwners {
	o.recentMu.RLock()
	state := o.recent[uid]
	o.recentMu.RUnlock()
	if state != nil {
		return state
	}
	candidate := new(recentOwners)
	o.recentMu.Lock()
	defer o.recentMu.Unlock()
	state = o.recent[uid]
	if state == nil {
		state = candidate
		o.recent[uid] = state
	}
	return state
}

func (o *Owners) recentPIDs(uid uint32) []uint32 {
	hints := o.recentFor(uid).hints.Load()
	if hints == nil {
		return nil
	}
	return hints.values[:hints.count]
}

// Hints are optional and every positive match is revalidated. A concurrent
// update may supersede this one; never wait or retry while a lookup's budget
// runs out. Immutable snapshots keep readers independent of these updates.
func (o *Owners) rememberPID(uid, pid uint32) {
	state := o.recentFor(uid)
	previous := state.hints.Load()
	if previous != nil && previous.values[0] == pid {
		return
	}
	next := &pidHints{count: 1}
	next.values[0] = pid
	if previous != nil {
		for _, candidate := range previous.values[:previous.count] {
			if candidate != pid && next.count < len(next.values) {
				next.values[next.count] = candidate
				next.count++
			}
		}
	}
	state.hints.CompareAndSwap(previous, next)
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

func (o *Owners) hasInodeWaiter(inode uint32) bool {
	s := o.indexFor(inode)
	s.mu.Lock()
	waiting := s.waiters[inode] != nil
	s.mu.Unlock()
	return waiting
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
