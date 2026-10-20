//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

type descriptorBatchKey struct {
	pid, uid         uint32
	start, directory uint64
	offset           int64
	limit            int
	advance          bool
	cacheAll         bool
}

type descriptorSocket struct {
	inode uint32
	fd    int64
}

type descriptorBatchResult struct {
	count   int
	lastFD  int64
	sockets []descriptorSocket
	began   time.Time
	err     error
}

type descriptorBatch struct {
	key      descriptorBatchKey
	queued   time.Time
	deadline time.Time
	done     chan struct{}
	result   descriptorBatchResult // immutable after done closes
}

type descriptorBatches struct {
	mu                                                  sync.Mutex
	jobs                                                chan *descriptorBatch
	available                                           chan struct{}
	live                                                map[descriptorBatchKey]*descriptorBatch
	closed                                              atomic.Bool
	workers                                             sync.WaitGroup
	started, shared, early, fds, sockets, full, aborted atomic.Uint64
	queueNanos, serviceNanos, maxQueue, maxService      atomic.Uint64
}

type descriptorQueueBusy struct{ ready <-chan struct{} }

func (*descriptorQueueBusy) Error() string { return "descriptor scanner queue is full" }

// A worker publishes a bounded descriptor window. Its caller can validate a
// published match immediately while the worker continues serving neighbours.
// Workers only touch kernel proc directories; process-root metadata stays in
// the caller, outside the shared worker pool.
func (o *Owners) descriptorBatch(key descriptorBatchKey) (*descriptorBatch, error) {
	b := &o.batches
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed.Load() {
		return nil, context.Canceled
	}
	if previous := b.live[key]; previous != nil {
		b.shared.Add(1)
		return previous, nil
	}
	if b.jobs == nil {
		b.jobs = make(chan *descriptorBatch, 128)
		b.available = make(chan struct{})
		b.live = make(map[descriptorBatchKey]*descriptorBatch)
		for range max(1, min(4, runtime.GOMAXPROCS(0)/2)) {
			b.workers.Add(1)
			go o.runDescriptorBatches()
		}
	}
	queued := time.Now()
	job := &descriptorBatch{key: key, queued: queued, deadline: queued.Add(8 * time.Millisecond), done: make(chan struct{})}
	select {
	case b.jobs <- job:
		b.live[key] = job
		b.started.Add(1)
		return job, nil
	default:
		b.full.Add(1)
		return nil, &descriptorQueueBusy{ready: b.available}
	}
}

func (o *Owners) closeDescriptorBatches() {
	b := &o.batches
	b.mu.Lock()
	if !b.closed.Swap(true) && b.jobs != nil {
		close(b.jobs)
		close(b.available)
		b.available = nil
	}
	b.mu.Unlock()
	b.workers.Wait()
}

func (o *Owners) runDescriptorBatches() {
	b := &o.batches
	defer b.workers.Done()
	for job := range b.jobs {
		started := time.Now()
		queued := uint64(started.Sub(job.queued))
		b.queueNanos.Add(queued)
		recordLookupMaximum(&b.maxQueue, queued)
		job.result = o.readDescriptorBatch(job)
		service := uint64(time.Since(started))
		b.serviceNanos.Add(service)
		recordLookupMaximum(&b.maxService, service)
		if errors.Is(job.result.err, context.DeadlineExceeded) || errors.Is(job.result.err, context.Canceled) {
			b.aborted.Add(1)
		}
		b.mu.Lock()
		delete(b.live, job.key)
		if b.available != nil {
			close(b.available)
			b.available = make(chan struct{})
		}
		close(job.done)
		b.mu.Unlock()
	}
}

func (o *Owners) readDescriptorBatch(job *descriptorBatch) descriptorBatchResult {
	k := job.key
	out := descriptorBatchResult{lastFD: -1, began: time.Now()}
	expired := func() bool { return o.batches.closed.Load() || !time.Now().Before(job.deadline) }
	if expired() {
		out.err = context.DeadlineExceeded
		return out
	}
	f, err := openProcDescriptors(fmt.Sprintf("/proc/%d/fd", k.pid))
	if err != nil {
		out.err = err
		return out
	}
	defer f.Close()
	var metadata unix.Stat_t
	if err := unix.Fstat(f.fd, &metadata); err != nil {
		out.err = err
		return out
	}
	if metadata.Ino != k.directory {
		out.err = unix.ESTALE
		return out
	}
	if _, err := f.Seek(k.offset, 0); err != nil {
		out.err = err
		return out
	}
	found := make(map[uint32]holder, 32)
	out.count, out.err = f.Visit(k.limit, func(name []byte) bool {
		if expired() {
			return false
		}
		fd, err := strconv.ParseInt(string(name), 10, 64)
		if err != nil {
			return true
		}
		out.lastFD = max(out.lastFD, fd)
		inode, ok := socketInodeAt(f.fd, string(name))
		if !ok {
			return true
		}
		out.sockets = append(out.sockets, descriptorSocket{inode: inode, fd: fd})
		// Foreign processes share the same bounded directory work too. Keep
		// their compact results for callers, but retain only requested positive
		// hints globally so the engine's own sockets do not double the index.
		if k.cacheAll || o.hasInodeWaiter(inode) {
			found[inode] = holder{pid: k.pid, start: k.start, fd: string(name)}
		}
		if len(found) == 32 {
			o.publish(found)
			clear(found)
		}
		return true
	})
	o.publish(found)
	if expired() && out.err == nil {
		out.err = context.DeadlineExceeded
	}
	o.batches.fds.Add(uint64(out.count))
	o.batches.sockets.Add(uint64(len(out.sockets)))
	o.mu.Lock()
	if current := o.windows[k.pid]; current.directory == k.directory && current.start == k.start {
		current.extent = max(current.extent, out.lastFD)
		if k.advance {
			current.high = max(current.high, out.lastFD)
		}
		current.observed = time.Now()
		if k.offset == 0 && k.cacheAll && errors.Is(out.err, io.EOF) {
			current.fullScan, current.fullUID = out.began, k.uid
			current.fdCount = metadata.Size
		}
		o.windows[k.pid] = current
	}
	o.mu.Unlock()
	return out
}
