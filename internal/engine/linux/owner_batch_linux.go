//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"hash/maphash"
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
	inode, fd uint32
}

type descriptorBatchResult struct {
	count   int
	lastFD  int64
	sockets []descriptorSocket
	began   time.Time
	err     error
}

type descriptorBatch struct {
	key                                                   descriptorBatchKey
	queued                                                time.Time
	deadline                                              time.Time
	caller                                                context.Context // non-nil only for caller-owned conflict scans
	inline                                                bool
	registered                                            bool // this job owns a live-map entry until completion/replacement
	done                                                  chan struct{}
	completed                                             time.Time
	result                                                descriptorBatchResult // immutable after done closes
	stage                                                 atomic.Uint32
	visited                                               atomic.Int64
	trace                                                 descriptorTrace
	queueAtEnqueue, inFlightAtEnqueue                     int64
	startedNS, completedNS, queueAtStart, inFlightAtStart atomic.Int64
	openedFDPlusOne                                       atomic.Int64
}

type descriptorBatches struct {
	mu                                                     sync.RWMutex // registration versus Close
	init                                                   sync.Once
	liveMu                                                 sync.Mutex // asynchronous jobs and queue notification
	jobs                                                   chan *descriptorBatch
	available                                              chan struct{}
	live                                                   map[descriptorBatchKey]*descriptorBatch
	recent                                                 [128]atomic.Pointer[descriptorBatch]
	closed                                                 atomic.Bool
	workers                                                sync.WaitGroup
	started, shared, early, fds, sockets, full, aborted    atomic.Uint64
	queueNanos, serviceNanos, maxQueue, maxService         atomic.Uint64
	reused, staleRetries, conflictWaits                    atomic.Uint64
	inline                                                 atomic.Uint64
	completionNanos, resumeNanos, maxCompletion, maxResume atomic.Uint64
	lockNanos, unlockNanos, maxLock, maxUnlock             atomic.Uint64
	lastWait                                               atomic.Pointer[string]
	active                                                 atomic.Int64
	failureSequence                                        atomic.Uint64
	failures                                               [8]atomic.Pointer[descriptorFailure]
	slowSequence                                           atomic.Uint64
	slow                                                   [8]atomic.Pointer[descriptorFailure]
}

type descriptorQueueBusy struct{ ready <-chan struct{} }

func (*descriptorQueueBusy) Error() string { return "descriptor scanner queue is full" }

// A worker publishes a bounded descriptor window. Its caller can validate a
// published match immediately while the worker continues serving neighbours.
// Workers only touch kernel proc directories; process-root metadata stays in
// the caller, outside the shared worker pool.
func (o *Owners) descriptorBatch(ctx context.Context, key descriptorBatchKey, requested time.Time, inline bool) (*descriptorBatch, error) {
	b := &o.batches
	acquiring := time.Now()
	b.mu.RLock()
	locked := uint64(time.Since(acquiring))
	b.lockNanos.Add(locked)
	recordLookupMaximum(&b.maxLock, locked)
	if b.closed.Load() {
		b.mu.RUnlock()
		return nil, context.Canceled
	}
	b.init.Do(func() {
		if b.jobs != nil {
			return
		}
		b.jobs = make(chan *descriptorBatch, 128)
		b.available = make(chan struct{})
		b.live = make(map[descriptorBatchKey]*descriptorBatch)
		for range max(1, min(4, runtime.GOMAXPROCS(0)/2)) {
			b.workers.Add(1)
			go o.runDescriptorBatches()
		}
	})
	// An overlapping lookup may reach this range after the worker finished.
	// Reuse only work begun during that lookup; older negatives cannot prove
	// anything about a descriptor opened since. Positive hints stay subject
	// to the caller's normal live FD and process identity checks.
	if previous := b.recent[maphash.Comparable(o.indexSeed, key)%uint64(len(b.recent))].Load(); previous != nil && previous.key == key && !previous.result.began.Before(requested) {
		b.reused.Add(1)
		b.mu.RUnlock()
		return previous, nil
	}
	// Allocation cannot hold the active-job map lock. Completed snapshots
	// and independent conflict reads do not need that exclusive lock at all.
	queued := time.Now()
	job := &descriptorBatch{key: key, queued: queued, deadline: queued.Add(8 * time.Millisecond), done: make(chan struct{}), inline: inline}
	job.queueAtEnqueue, job.inFlightAtEnqueue = int64(len(b.jobs)), b.active.Load()
	if inline {
		job.caller = ctx
		if deadline, ok := ctx.Deadline(); ok && deadline.Before(job.deadline) {
			job.deadline = deadline
		}
		canRun := len(b.jobs) < cap(b.jobs)
		// Share bounded live work, including an older pass: a follower must
		// still request a fresh pass before trusting an older negative. That
		// second pass can serve all callers which arrived during the first.
		// A busy registration lock never holds up an independent live read.
		if b.liveMu.TryLock() {
			if previous := b.live[key]; previous != nil && previous.deadline.After(time.Now()) {
				b.shared.Add(1)
				b.liveMu.Unlock()
				b.mu.RUnlock()
				return previous, nil
			}
			if canRun {
				b.live[key] = job
				job.registered = true
			}
			b.liveMu.Unlock()
		}
		if canRun {
			b.started.Add(1)
			b.inline.Add(1)
			b.workers.Add(1)
			b.mu.RUnlock()
			o.completeDescriptorBatch(job)
			b.workers.Done()
			return job, nil
		}
	}
	acquiring = time.Now()
	b.liveMu.Lock()
	locked = uint64(time.Since(acquiring))
	b.lockNanos.Add(locked)
	recordLookupMaximum(&b.maxLock, locked)
	if previous := b.live[key]; previous != nil && previous.deadline.After(time.Now()) {
		b.shared.Add(1)
		b.liveMu.Unlock()
		b.mu.RUnlock()
		return previous, nil
	}
	if inline {
		b.full.Add(1)
		err := &descriptorQueueBusy{ready: b.available}
		b.liveMu.Unlock()
		b.mu.RUnlock()
		return nil, err
	}
	select {
	case b.jobs <- job:
		b.live[key] = job
		b.started.Add(1)
		b.liveMu.Unlock()
		b.mu.RUnlock()
		return job, nil
	default:
		b.full.Add(1)
		err := &descriptorQueueBusy{ready: b.available}
		b.liveMu.Unlock()
		b.mu.RUnlock()
		return nil, err
	}
}

func (o *Owners) closeDescriptorBatches() {
	b := &o.batches
	b.mu.Lock()
	if !b.closed.Swap(true) && b.jobs != nil {
		close(b.jobs)
		b.liveMu.Lock()
		available := b.available
		b.available = nil
		b.liveMu.Unlock()
		if available != nil {
			close(available)
		}
	}
	b.mu.Unlock()
	b.workers.Wait()
}

func (o *Owners) runDescriptorBatches() {
	b := &o.batches
	defer b.workers.Done()
	for job := range b.jobs {
		o.completeDescriptorBatch(job)
	}
}

func (o *Owners) completeDescriptorBatch(job *descriptorBatch) {
	b := &o.batches
	job.stage.Store(1)
	started := time.Now()
	job.startedNS.Store(started.UnixNano())
	job.queueAtStart.Store(int64(len(b.jobs)))
	job.inFlightAtStart.Store(b.active.Add(1))
	defer b.active.Add(-1)
	queued := uint64(started.Sub(job.queued))
	b.queueNanos.Add(queued)
	recordLookupMaximum(&b.maxQueue, queued)
	job.result = o.readDescriptorBatch(job)
	job.stage.Store(5)
	job.caller = nil
	serviced := time.Now()
	service := uint64(serviced.Sub(started))
	b.serviceNanos.Add(service)
	recordLookupMaximum(&b.maxService, service)
	if errors.Is(job.result.err, context.DeadlineExceeded) || errors.Is(job.result.err, context.Canceled) {
		b.aborted.Add(1)
	}
	var available chan struct{}
	if !job.inline || job.registered {
		var nextAvailable chan struct{}
		if !job.inline {
			nextAvailable = make(chan struct{})
		}
		b.liveMu.Lock()
		if b.live[job.key] == job {
			delete(b.live, job.key)
		}
		if !job.inline && b.available != nil {
			available = b.available
			if b.closed.Load() {
				b.available = nil
			} else {
				b.available = nextAvailable
			}
		}
		unlocking := time.Now()
		b.liveMu.Unlock()
		unlocked := uint64(time.Since(unlocking))
		b.unlockNanos.Add(unlocked)
		recordLookupMaximum(&b.maxUnlock, unlocked)
	}
	job.completed = time.Now()
	job.completedNS.Store(job.completed.UnixNano())
	completion := uint64(job.completed.Sub(serviced))
	b.completionNanos.Add(completion)
	recordLookupMaximum(&b.maxCompletion, completion)
	// Publish the immutable result before notifying callers. Neither step
	// holds a lock that another lookup must acquire.
	if job.result.err == nil || errors.Is(job.result.err, io.EOF) {
		slot := &b.recent[maphash.Comparable(o.indexSeed, job.key)%uint64(len(b.recent))]
		for previous := slot.Load(); previous == nil || previous.result.began.Before(job.result.began); previous = slot.Load() {
			if slot.CompareAndSwap(previous, job) {
				break
			}
		}
	}
	close(job.done)
	job.stage.Store(6)
	if available != nil {
		close(available)
	}
}

func (o *Owners) recordBatchWait(ctx context.Context, job *descriptorBatch, row socketRow, requested time.Time) {
	stage := job.stage.Load()
	message := fmt.Sprintf("stage=%s pid=%d offset=%d limit=%d visited=%d age=%s expired=%t queued=%d inline=%t", descriptorStage(stage), job.key.pid, job.key.offset, job.key.limit, job.visited.Load(), time.Since(job.queued), time.Now().After(job.deadline), len(o.batches.jobs), job.inline)
	o.batches.lastWait.Store(&message)
	failure := observeDescriptorBatch(ctx, job, row, requested, "deadline")
	sequence := o.batches.failureSequence.Add(1)
	o.batches.failures[(sequence-1)%uint64(len(o.batches.failures))].Store(failure)
}

func (b *descriptorBatches) resumed(job *descriptorBatch, waiting time.Time) {
	if !job.completed.IsZero() && !job.completed.Before(waiting) {
		delay := uint64(time.Since(job.completed))
		b.resumeNanos.Add(delay)
		recordLookupMaximum(&b.maxResume, delay)
	}
}

func (o *Owners) readDescriptorBatch(job *descriptorBatch) descriptorBatchResult {
	k := job.key
	out := descriptorBatchResult{lastFD: -1, began: time.Now()}
	expired := func() bool {
		return o.batches.closed.Load() || !time.Now().Before(job.deadline) || (job.caller != nil && job.caller.Err() != nil)
	}
	if expired() {
		out.err = context.DeadlineExceeded
		return out
	}
	job.stage.Store(2)
	read := job.trace.begin(-3)
	f, err := openProcDescriptors(fmt.Sprintf("/proc/%d/fd", k.pid))
	job.trace.end(read)
	if err == nil {
		job.openedFDPlusOne.Store(int64(f.fd) + 1)
	}
	if err != nil {
		out.err = err
		return out
	}
	defer func() { job.stage.Store(8); f.Close() }()
	f.trace = &job.trace
	var metadata unix.Stat_t
	read = job.trace.begin(-4)
	err = statKernelFile(f.fd, f.direct, &metadata)
	job.trace.end(read)
	if err != nil {
		out.err = err
		return out
	}
	if metadata.Ino != k.directory {
		out.err = unix.ESTALE
		return out
	}
	read = job.trace.begin(-5)
	_, err = f.Seek(k.offset, 0)
	job.trace.end(read)
	if err != nil {
		out.err = err
		return out
	}
	job.stage.Store(3)
	out.count, out.err = f.Visit(k.limit, func(name []byte) bool {
		job.visited.Add(1)
		if expired() {
			return false
		}
		fd, err := strconv.ParseUint(string(name), 10, 32)
		if err != nil {
			return true
		}
		out.lastFD = max(out.lastFD, int64(fd))
		read := job.trace.begin(int64(fd))
		inode, ok := socketInodeAt(f.fd, string(name))
		job.trace.end(read)
		if !ok {
			return true
		}
		if out.sockets == nil {
			out.sockets = make([]descriptorSocket, 0, min(k.limit, 64))
		}
		out.sockets = append(out.sockets, descriptorSocket{inode: inode, fd: uint32(fd)})
		// Foreign processes share the same bounded directory work too. Keep
		// their compact results for callers, but retain only requested positive
		// hints globally so the engine's own sockets do not double the index.
		if k.cacheAll || o.hasInodeWaiter(inode) {
			job.stage.Store(4)
			o.publishHolder(inode, holder{pid: k.pid, start: k.start, fd: string(name)})
			job.stage.Store(3)
		}
		return true
	})
	if expired() && out.err == nil {
		out.err = context.DeadlineExceeded
	}
	o.batches.fds.Add(uint64(out.count))
	o.batches.sockets.Add(uint64(len(out.sockets)))
	job.stage.Store(7)
	o.mu.Lock()
	if current := o.windows[k.pid]; current.directory == k.directory && current.start == k.start {
		current.extent = max(current.extent, out.lastFD)
		if k.advance {
			current.high = max(current.high, out.lastFD)
		}
		current.observed = time.Now()
		if k.offset == 0 && k.cacheAll && errors.Is(out.err, io.EOF) && current.fullScan.Before(out.began) {
			current.fullScan, current.fullUID = out.began, k.uid
			current.fdCount = metadata.Size
		}
		o.windows[k.pid] = current
	}
	o.mu.Unlock()
	return out
}
