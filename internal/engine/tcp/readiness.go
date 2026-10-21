package tcp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Each relay is queued at most once, including while a worker owns it. Waiter
// callbacks run under gVisor locks: they only enqueue, never perform I/O, wait
// for a worker, unregister themselves, or acquire an endpoint lock.
type relayWorkers struct {
	mu         sync.Mutex
	head, tail *readyRelay
	wake       chan struct{}
	stop       chan struct{}
	stopOnce   sync.Once
	wg         sync.WaitGroup
	finished   *sync.Cond
	bufferMu   sync.Mutex
	loans      int
	bufferPeak int
	waiting    []*readyRelay
	appLoans   map[string]int
}

// Loans cover only a synchronous peek/write/discard operation. A stalled
// destination leaves its bytes in the source socket and returns the loan.
// FIFO reservations prevent a previous holder overtaking a waiting relay.
const RelayHeldBudget = 16 << 20
const RelayAppLoans = 32

type relayDirection struct {
	blocked, finished bool
}

// Endpoint I/O consumes these adapters synchronously. Reuse them per worker
// rather than allocating an interface-backed reader/writer for every chunk.
type relayScratch struct {
	receive tcpip.SliceWriter
	discard discardWriter
	send    bytes.Reader
	buffer  [RelayBuffer]byte
}

// discardWriter consumes up to n bytes from the app's endpoint without
// copying them: the relay has already peeked and sent them. gVisor's
// endpoint Read trims exactly what a writer accepted, so a short write leaves
// the rest queued, as SliceWriter's would.
type discardWriter struct{ n int }

func (d *discardWriter) Write(b []byte) (int, error) {
	if len(b) <= d.n {
		d.n -= len(b)
		return len(b), nil
	}
	n := d.n
	d.n = 0
	return n, io.ErrShortWrite
}

type readyRelay struct {
	workers                        *relayWorkers
	next                           *readyRelay
	initializing, scheduled, again bool // workers.mu
	closed                         atomic.Bool
	cancelled                      atomic.Bool
	ctx                            context.Context
	c                              *connection
	connection                     connection
	queue                          waiter.Queue
	forward                        *Forwarder
	remote                         platform.ReadyTCP
	watch                          platform.Readiness
	wq                             *waiter.Queue
	entry                          waiter.Entry
	up, down                       relayDirection
	waitBuffer                     bool // worker only
	app                            string
	queued, granted                bool // workers.bufferMu
}

func newRelayWorkers() *relayWorkers {
	// Leave scheduling capacity for ordered ingress, the TUN writer and
	// ACK processing. Relay work alone must not occupy every processor while
	// its writes wait for those same consumers to make progress.
	n := min(8, max(1, (runtime.GOMAXPROCS(0)+1)/2))
	w := &relayWorkers{wake: make(chan struct{}, n), stop: make(chan struct{}), appLoans: make(map[string]int)}
	w.finished = sync.NewCond(&w.mu)
	for range n {
		w.wg.Go(w.run)
	}
	return w
}

func (w *relayWorkers) borrow(r *readyRelay) bool {
	w.bufferMu.Lock()
	defer w.bufferMu.Unlock()
	if r.granted {
		r.granted = false
		return true
	}
	if r.queued || len(w.waiting) != 0 || w.loans == RelayHeldBudget/RelayBuffer || w.appLoans[r.app] == RelayAppLoans {
		if !r.queued {
			r.queued = true
			w.waiting = append(w.waiting, r)
		}
		r.waitBuffer = true
		w.grantLocked()
		return false
	}
	w.reserveLocked(r)
	return true
}

func (w *relayWorkers) reserveLocked(r *readyRelay) {
	if w.appLoans == nil {
		w.appLoans = make(map[string]int)
	}
	w.appLoans[r.app]++
	w.loans++
	w.bufferPeak = max(w.bufferPeak, w.loans)
}

func (w *relayWorkers) giveBack(r *readyRelay) {
	w.bufferMu.Lock()
	w.returnLocked(r)
	w.grantLocked()
	w.bufferMu.Unlock()
}

func (w *relayWorkers) returnLocked(r *readyRelay) {
	w.loans--
	w.appLoans[r.app]--
	if w.appLoans[r.app] == 0 {
		delete(w.appLoans, r.app)
	}
}

func (w *relayWorkers) grantLocked() {
	kept := w.waiting[:0]
	for _, r := range w.waiting {
		if r.closed.Load() {
			r.queued = false
			continue
		}
		if w.loans < RelayHeldBudget/RelayBuffer && w.appLoans[r.app] < RelayAppLoans {
			w.reserveLocked(r)
			r.queued, r.granted = false, true
			r.notify()
		} else {
			kept = append(kept, r)
		}
	}
	clear(w.waiting[len(kept):])
	w.waiting = kept
}

func (f *Forwarder) RelayBufferBytes() (int, int) {
	w := f.relays
	w.bufferMu.Lock()
	defer w.bufferMu.Unlock()
	return w.loans * RelayBuffer, w.bufferPeak * RelayBuffer
}

func (r *readyRelay) notify() {
	w := r.workers
	w.mu.Lock()
	if r.closed.Load() {
		w.mu.Unlock()
		return
	}
	if r.initializing || r.scheduled {
		r.again = true
		w.mu.Unlock()
		return
	}
	r.scheduled = true
	w.appendLocked(r)
	w.mu.Unlock()
}

func (w *relayWorkers) appendLocked(r *readyRelay) {
	if w.tail == nil {
		w.head = r
	} else {
		w.tail.next = r
	}
	w.tail = r
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

func (w *relayWorkers) run() {
	scratch := new(relayScratch)
	for {
		select {
		case <-w.stop:
			return
		case <-w.wake:
		}
		for {
			w.mu.Lock()
			r := w.head
			if r != nil {
				w.head = r.next
				if w.head == nil {
					w.tail = nil
				}
				r.next, r.again = nil, false
			}
			w.mu.Unlock()
			if r == nil {
				break
			}
			r.step(scratch)
			w.mu.Lock()
			if r.again && !r.closed.Load() {
				w.appendLocked(r)
			} else {
				r.scheduled = false
			}
			w.mu.Unlock()
			// A continuously readable connection must not keep every P until
			// Go's preemption interval (longer than the owner lookup budget).
			// Yield between bounded I/O quanta so admission and TUN ingress run.
			runtime.Gosched()
		}
	}
}

func (w *relayWorkers) close() {
	w.stopOnce.Do(func() { close(w.stop) })
	w.wg.Wait()
}

func (f *Forwarder) startReadyRelay(ctx context.Context, r *readyRelay, remote platform.ReadyTCP, app string) error {
	c, wq := r.c, &r.queue
	r.workers, r.initializing, r.ctx, r.remote, r.wq, r.app, r.forward = f.relays, true, f.ctx, remote, wq, app, f
	r.cancelled.Store(ctx.Err() != nil)
	watch, err := remote.Watch(r.notify)
	if err != nil {
		return err
	}
	r.watch = watch
	r.entry.Init(r, waiter.ReadableEvents|waiter.WritableEvents|waiter.EventErr|waiter.EventHUp)
	wq.EventRegister(&r.entry)
	f.wg.Add(1)
	// Once setup is finished, closure is an atomic flag and a work item.
	// Keep no per-flow cancellation context or AfterFunc: cancelling 65,536
	// children must not create 65,536 temporary cleanup goroutines either.
	c.ticket.SetCancel(r.cancel)
	c.ready.Store(r)
	f.relays.mu.Lock()
	r.initializing = false
	f.relays.mu.Unlock()
	r.notify()
	return nil
}

func (r *readyRelay) cancel()                      { r.cancelled.Store(true); r.notify() }
func (r *readyRelay) NotifyEvent(waiter.EventMask) { r.notify() }

func (f *Forwarder) completeConnection(c *connection) {
	f.relays.mu.Lock()
	c.completed.Store(true)
	f.relays.finished.Broadcast()
	f.relays.mu.Unlock()
}

func (r *readyRelay) close(abort bool) {
	if r.closed.Swap(true) {
		return
	}
	r.watch.Detach()
	r.wq.EventUnregister(&r.entry)
	r.workers.bufferMu.Lock()
	if r.granted {
		r.granted = false
		r.workers.returnLocked(r)
	}
	r.workers.grantLocked()
	r.workers.bufferMu.Unlock()
	if abort {
		r.remote.SetLinger(0)
		if closeAdmissionEnabled {
			r.c.ticket.Retire()
		}
		r.c.ep.Abort()
	}
	r.remote.Close()
	r.c.ep.Close()
	r.c.releaseAdmission()
	r.forward.completeConnection(r.c)
	r.forward.wg.Done()
}

func stackError(err tcpip.Error) error {
	switch err.(type) {
	case nil:
		return nil
	case *tcpip.ErrWouldBlock:
		return platform.ErrWouldBlock
	case *tcpip.ErrClosedForReceive:
		return io.EOF
	default:
		return errors.New(err.String())
	}
}

func (r *readyRelay) read(up bool, b []byte, scratch *relayScratch) (int, error) {
	if !up {
		return r.remote.TryPeek(b)
	}
	scratch.receive = tcpip.SliceWriter(b)
	result, err := r.c.ep.Read(&scratch.receive, tcpip.ReadOptions{Peek: true})
	scratch.receive = nil
	return result.Count, stackError(err)
}

func (r *readyRelay) discard(up bool, b []byte, scratch *relayScratch) error {
	for len(b) > 0 {
		var n int
		var err error
		if up {
			scratch.discard = discardWriter{n: len(b)}
			result, e := r.c.ep.Read(&scratch.discard, tcpip.ReadOptions{})
			n, err = result.Count, stackError(e)
		} else {
			n, err = r.remote.TryDiscard(b)
		}
		if n < 0 || n > len(b) {
			return io.ErrShortBuffer
		}
		b = b[n:]
		if len(b) == 0 {
			return nil
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func (r *readyRelay) write(up bool, b []byte, scratch *relayScratch) (int, error) {
	if up {
		return r.remote.TryWrite(b)
	}
	scratch.send.Reset(b)
	n, err := r.c.ep.Write(&scratch.send, tcpip.WriteOptions{})
	scratch.send.Reset(nil)
	return int(n), stackError(err)
}

func (r *readyRelay) direction(d *relayDirection, up bool, scratch *relayScratch) (bool, error) {
	if d.finished {
		return false, nil
	}
	d.blocked = false
	// A busy flow yields after a bounded amount of work, so it cannot starve
	// other readiness events, the ordered TUN reader, or process lookups.
	for moved, operations := 0, 0; moved < 256<<10 && operations < 32; operations++ {
		if !r.workers.borrow(r) {
			return false, nil
		}
		peeked, readErr := r.read(up, scratch.buffer[:], scratch)
		if peeked < 0 || peeked > len(scratch.buffer) {
			r.workers.giveBack(r)
			return false, io.ErrShortBuffer
		}
		if peeked > 0 {
			n, err := r.write(up, scratch.buffer[:peeked], scratch)
			if n < 0 || n > peeked {
				r.workers.giveBack(r)
				return false, io.ErrShortWrite
			}
			if consumeErr := r.discard(up, scratch.buffer[:n], scratch); consumeErr != nil {
				r.workers.giveBack(r)
				return false, consumeErr
			}
			r.workers.giveBack(r)
			if n > 0 {
				moved += n
				if up {
					r.c.up.Add(uint64(n))
					r.c.ticket.Add(uint64(n), 0)
				} else {
					r.c.down.Add(uint64(n))
					r.c.ticket.Add(0, uint64(n))
				}
			}
			if errors.Is(err, platform.ErrWouldBlock) {
				d.blocked = true
				return false, nil
			}
			if err != nil {
				return false, err
			}
			if n == 0 {
				return false, io.ErrNoProgress
			}
			// Re-peek even after a short successful write. EOF is propagated
			// only once every byte before it has actually been consumed.
			continue
		}
		r.workers.giveBack(r)
		if errors.Is(readErr, platform.ErrWouldBlock) {
			return false, nil
		}
		if errors.Is(readErr, io.EOF) {
			d.finished = true
			if up {
				if err := r.remote.CloseWrite(); err != nil {
					return false, err
				}
				// Receive shutdown is cleanup, as in Splice. A peer's FIN can
				// already have moved the endpoint into TIME_WAIT, where another
				// ShutdownRead reports not-connected. It must not abort the
				// lost-final-ACK protection we just established.
				r.c.ep.Shutdown(tcpip.ShutdownRead)
				return false, nil
			}
			if err := stackError(r.c.ep.Shutdown(tcpip.ShutdownWrite)); err != nil {
				return false, err
			}
			r.c.releaseAdmission()
			r.remote.CloseRead()
			return false, nil
		}
		if readErr != nil {
			return false, readErr
		}
		return false, io.ErrNoProgress
	}
	return true, nil
}

func (r *readyRelay) step(scratch *relayScratch) {
	r.waitBuffer = false
	if r.cancelled.Load() || r.ctx.Err() != nil {
		r.close(true)
		return
	}
	up, err := r.direction(&r.up, true, scratch)
	if err != nil {
		r.close(true)
		return
	}
	down, err := r.direction(&r.down, false, scratch)
	if err != nil {
		r.close(true)
		return
	}
	if r.up.finished && r.down.finished {
		r.close(false)
		return
	}
	if err := r.watch.Arm(!r.waitBuffer && !r.down.finished && !r.down.blocked, r.up.blocked); err != nil {
		r.close(true)
		return
	}
	if up || down {
		r.notify()
	}
}
