//go:build linux

package linux

import (
	"context"
	"sync"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

// A validation can serve overlapping lookups only when it began after each
// caller checked its own descriptor. This is not a TTL identity cache: a new
// lookup after the read must perform another read, including after exec or a
// mount-namespace change with the same PID and process start time.
type ownerValidation struct {
	pid      uint32
	start    uint64
	mu       sync.Mutex
	complete bool
	began    time.Time
	owner    platform.Owner
	err      error
}

func (o *Owners) invalidateStart(h holder) {
	o.mu.Lock()
	defer o.mu.Unlock()
	window := o.windows[h.pid]
	if window.start == h.start {
		window.start, window.next, window.high, window.extent = 0, 0, 0, 0
		window.lastFD, window.tailProbed, window.identity = -1, false, nil
		window.fullScan = time.Time{}
		o.windows[h.pid] = window
	}
}

func (o *Owners) validationFor(h holder) *ownerValidation {
	o.mu.Lock()
	window := o.windows[h.pid]
	if window.start == h.start && window.identity != nil {
		value := window.identity
		o.mu.Unlock()
		return value
	}
	o.mu.Unlock()
	value := &ownerValidation{pid: h.pid, start: h.start}
	o.mu.Lock()
	window = o.windows[h.pid]
	if window.start == h.start {
		if window.identity != nil {
			value = window.identity
		} else {
			window.identity = value
			o.windows[h.pid] = window
		}
	}
	o.mu.Unlock()
	return value
}

func (v *ownerValidation) resolve(ctx context.Context, checked time.Time, o *Owners) (platform.Owner, error) {
	if err := ctx.Err(); err != nil {
		return platform.Owner{}, err
	}
	// Metadata is a best-effort completed result, never a gate. A reader
	// descheduled in procfs or while publishing cannot stop every follower.
	if v.mu.TryLock() {
		if v.complete && !v.began.Before(checked) {
			owner, err := v.owner, v.err
			v.mu.Unlock()
			o.sharedMetadata.Add(1)
			return owner, err
		}
		v.mu.Unlock()
	}
	began := time.Now()
	o.metadataPasses.Add(1)
	owner, err := processOwnerAt(v.pid, v.start)
	if v.mu.TryLock() {
		if !v.complete || v.began.Before(began) {
			v.began, v.owner, v.err, v.complete = began, owner, err, true
		}
		v.mu.Unlock()
	}
	return owner, err
}
