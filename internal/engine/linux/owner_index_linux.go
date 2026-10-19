//go:build linux

package linux

import "slices"

// The common one-holder entry lives directly in the map. Publishing a batch
// of new sockets therefore needs no per-entry allocation under Owners.mu.
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
	o.mu.Lock()
	h := o.inodes[inode]
	o.mu.Unlock()
	return h
}
func (o *Owners) subscribe(inode uint32) *inodeWaiter {
	w := &inodeWaiter{ready: make(chan struct{})}
	o.mu.Lock()
	w.next = o.waiters[inode]
	o.waiters[inode] = w
	o.mu.Unlock()
	return w
}
func (o *Owners) unsubscribe(inode uint32, w *inodeWaiter) {
	o.mu.Lock()
	defer o.mu.Unlock()
	var previous *inodeWaiter
	for current := o.waiters[inode]; current != nil; current = current.next {
		if current == w {
			if previous != nil {
				previous.next = current.next
			} else if current.next != nil {
				o.waiters[inode] = current.next
			} else {
				delete(o.waiters, inode)
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
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.inodes) > 131072 {
		clear(o.inodes)
	}
	for inode, h := range found {
		old := o.inodes[inode]
		changed := false
		if old.first.pid == 0 {
			old.first = h
			changed = true
		} else if old.first != h && !slices.Contains(old.more, h) && len(old.more) < 7 {
			old.more = append(old.more, h)
			changed = true
		}
		if changed {
			o.inodes[inode] = old
		}
		// Wake only lookups for this inode, while the rest of the descriptor
		// batch is still being indexed. A 512-entry batch must not hold every
		// new connection's result until its last readlink completes.
		for w := o.waiters[inode]; w != nil; w = w.next {
			close(w.ready)
		}
		delete(o.waiters, inode)
	}
}
