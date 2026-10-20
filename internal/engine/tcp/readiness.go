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
	wg         sync.WaitGroup
}

type relayDirection struct {
	buffer        *[]byte
	start, end    int
	eof, finished bool
}

// Endpoint I/O consumes these adapters synchronously. Reuse them per worker
// rather than allocating an interface-backed reader/writer for every chunk.
type relayScratch struct {
	receive tcpip.SliceWriter
	send    bytes.Reader
	buffer  [RelayBuffer]byte
}

type readyRelay struct {
	workers                        *relayWorkers
	next                           *readyRelay
	initializing, scheduled, again bool // workers.mu
	closed                         atomic.Bool
	cancelled                      atomic.Bool
	ctx                            context.Context
	c                              *connection
	remote                         platform.ReadyTCP
	watch                          platform.Readiness
	wq                             *waiter.Queue
	entry                          waiter.Entry
	up, down                       relayDirection
	finish                         func()
}

func newRelayWorkers() *relayWorkers {
	n := min(8, max(2, runtime.GOMAXPROCS(0)))
	w := &relayWorkers{wake: make(chan struct{}, n), stop: make(chan struct{})}
	for range n {
		w.wg.Go(w.run)
	}
	return w
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

func (w *relayWorkers) close() { close(w.stop); w.wg.Wait() }

func (f *Forwarder) startReadyRelay(ctx context.Context, c *connection, wq *waiter.Queue, remote platform.ReadyTCP, closeApp func()) error {
	r := &readyRelay{workers: f.relays, initializing: true, ctx: f.ctx, c: c, remote: remote, wq: wq}
	r.cancelled.Store(ctx.Err() != nil)
	watch, err := remote.Watch(r.notify)
	if err != nil {
		return err
	}
	r.watch = watch
	r.entry = waiter.NewFunctionEntry(waiter.ReadableEvents|waiter.WritableEvents|waiter.EventErr|waiter.EventHUp, func(waiter.EventMask) { r.notify() })
	wq.EventRegister(&r.entry)
	f.wg.Add(1)
	r.finish = func() {
		remote.Close()
		closeApp()
		c.releaseAdmission()
		close(c.done)
		f.wg.Done()
	}
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

func (r *readyRelay) cancel() { r.cancelled.Store(true); r.notify() }

func (r *readyRelay) close(abort bool) {
	if r.closed.Swap(true) {
		return
	}
	r.watch.Detach()
	r.wq.EventUnregister(&r.entry)
	if abort {
		r.remote.SetLinger(0)
		if closeAdmissionEnabled {
			r.c.ticket.Retire()
		}
		r.c.ep.Abort()
	}
	for _, d := range []*relayDirection{&r.up, &r.down} {
		if d.buffer != nil {
			relayBuffers.Put(d.buffer)
			d.buffer = nil
		}
	}
	r.finish()
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
		return r.remote.TryRead(b)
	}
	scratch.receive = tcpip.SliceWriter(b)
	result, err := r.c.ep.Read(&scratch.receive, tcpip.ReadOptions{})
	scratch.receive = nil
	return result.Count, stackError(err)
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
	// A busy flow yields after a bounded amount of work, so it cannot starve
	// other readiness events, the ordered TUN reader, or process lookups.
	for moved, operations := 0, 0; moved < 256<<10 && operations < 32; operations++ {
		var pending []byte
		if d.buffer != nil {
			pending = (*d.buffer)[d.start:d.end]
		} else if !d.eof {
			// A worker owns this scratch until step returns. The usual full
			// write needs no pool access or allocation, even during repeated
			// collections. Only blocked/short writes retain a private buffer.
			n, err := r.read(up, scratch.buffer[:], scratch)
			pending = scratch.buffer[:n]
			if errors.Is(err, io.EOF) {
				d.eof = true
			} else if errors.Is(err, platform.ErrWouldBlock) {
				if n == 0 {
					return false, nil
				}
			} else if err != nil {
				return false, err
			} else if n == 0 {
				return false, io.ErrNoProgress
			}
		}
		if len(pending) != 0 {
			n, err := r.write(up, pending, scratch)
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
			if d.buffer != nil {
				d.start += n
				if d.start == d.end {
					relayBuffers.Put(d.buffer)
					d.buffer = nil
				}
			} else if n < len(pending) {
				d.buffer = relayBuffers.Get().(*[]byte)
				d.start, d.end = 0, copy(*d.buffer, pending[n:])
			}
			if errors.Is(err, platform.ErrWouldBlock) {
				return false, nil
			}
			if err != nil {
				return false, err
			}
			if n == 0 {
				return false, io.ErrNoProgress
			}
		}
		if d.eof && d.buffer == nil {
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
	}
	return true, nil
}

func (r *readyRelay) step(scratch *relayScratch) {
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
	if err := r.watch.Arm(!r.down.finished && r.down.buffer == nil, r.up.buffer != nil); err != nil {
		r.close(true)
		return
	}
	if up || down {
		r.notify()
	}
}
