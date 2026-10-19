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

type readyRelay struct {
	workers                        *relayWorkers
	next                           *readyRelay
	initializing, scheduled, again bool // workers.mu
	closed                         atomic.Bool
	ctx                            context.Context
	c                              *connection
	remote                         platform.ReadyTCP
	watch                          platform.Readiness
	wq                             *waiter.Queue
	entry                          waiter.Entry
	up, down                       relayDirection
	stopCancel                     func() bool
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
			r.step()
			w.mu.Lock()
			if r.again && !r.closed.Load() {
				w.appendLocked(r)
			} else {
				r.scheduled = false
			}
			w.mu.Unlock()
		}
	}
}

func (w *relayWorkers) close() { close(w.stop); w.wg.Wait() }

func (f *Forwarder) startReadyRelay(ctx context.Context, c *connection, wq *waiter.Queue, remote platform.ReadyTCP, closeApp func(), cancel context.CancelFunc) error {
	r := &readyRelay{workers: f.relays, initializing: true, ctx: ctx, c: c, remote: remote, wq: wq}
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
		cancel()
		close(c.done)
		f.wg.Done()
	}
	r.stopCancel = context.AfterFunc(ctx, r.notify)
	f.relays.mu.Lock()
	r.initializing = false
	f.relays.mu.Unlock()
	r.notify()
	return nil
}

func (r *readyRelay) close(abort bool) {
	if r.closed.Swap(true) {
		return
	}
	r.stopCancel()
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

func (r *readyRelay) read(up bool, b []byte) (int, error) {
	if !up {
		return r.remote.TryRead(b)
	}
	w := tcpip.SliceWriter(b)
	result, err := r.c.ep.Read(&w, tcpip.ReadOptions{})
	return result.Count, stackError(err)
}

func (r *readyRelay) write(up bool, b []byte) (int, error) {
	if up {
		return r.remote.TryWrite(b)
	}
	reader := bytes.NewReader(b)
	n, err := r.c.ep.Write(reader, tcpip.WriteOptions{})
	return int(n), stackError(err)
}

func (r *readyRelay) direction(d *relayDirection, up bool) (bool, error) {
	if d.finished {
		return false, nil
	}
	// A busy flow yields after a bounded amount of work, so it cannot starve
	// other readiness events, the ordered TUN reader, or process lookups.
	for moved := 0; moved < 256<<10; {
		if d.buffer == nil && !d.eof {
			buffer := relayBuffers.Get().(*[]byte)
			n, err := r.read(up, *buffer)
			if n != 0 {
				d.buffer, d.start, d.end = buffer, 0, n
			} else {
				relayBuffers.Put(buffer)
			}
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
		if d.buffer != nil {
			n, err := r.write(up, (*d.buffer)[d.start:d.end])
			if n > 0 {
				d.start += n
				moved += n
				if up {
					r.c.up.Add(uint64(n))
					r.c.ticket.Add(uint64(n), 0)
				} else {
					r.c.down.Add(uint64(n))
					r.c.ticket.Add(0, uint64(n))
				}
			}
			if d.start == d.end {
				relayBuffers.Put(d.buffer)
				d.buffer = nil
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
				return false, stackError(r.c.ep.Shutdown(tcpip.ShutdownRead))
			}
			if err := stackError(r.c.ep.Shutdown(tcpip.ShutdownWrite)); err != nil {
				return false, err
			}
			r.c.releaseAdmission()
			return false, r.remote.CloseRead()
		}
	}
	return true, nil
}

func (r *readyRelay) step() {
	if r.ctx.Err() != nil {
		r.close(true)
		return
	}
	up, err := r.direction(&r.up, true)
	if err != nil {
		r.close(true)
		return
	}
	down, err := r.direction(&r.down, false)
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
