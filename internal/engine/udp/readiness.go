package udp

import (
	"errors"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

// Only setup uses a per-session goroutine. Idle native sessions live in the
// readiness poller; bounded shared workers own all subsequent I/O and teardown.
type udpWorkers struct {
	mu         sync.Mutex
	head, tail *readySession
	wake       chan struct{}
	stop       chan struct{}
	wg         sync.WaitGroup
}

type readySession struct {
	s                           *session
	socket                      platform.ReadyUDP
	watch                       platform.Readiness
	next                        *readySession
	initializing, queued, again bool      // workers.mu
	finished                    bool      // workers.mu
	pending                     *datagram // worker only
	readAfter                   time.Time // worker only
	backoff                     time.Duration
}

func newUDPWorkers() *udpWorkers {
	count := min(4, max(1, runtime.GOMAXPROCS(0)/2))
	w := &udpWorkers{wake: make(chan struct{}, count), stop: make(chan struct{})}
	for range count {
		w.wg.Go(w.run)
	}
	return w
}

func (s *session) startReady(socket platform.ReadyUDP) bool {
	r := &readySession{s: s, socket: socket, initializing: true}
	// Serialize Watch installation with close. An adapter may register OS
	// resources inside Watch, so even setup cancellation must detach before
	// closing its socket. Readiness callbacks take only the worker queue lock.
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return false
	}
	watch, err := socket.Watch(r.notify)
	if err != nil {
		s.mu.Unlock()
		s.n.ReadErrors.Add(1)
		return false
	}
	r.watch = watch
	s.cancel = nil
	s.ready.Store(r)
	s.mu.Unlock()
	s.ticket.SetCancel(s.close)
	w := s.n.io
	w.mu.Lock()
	r.initializing = false
	w.mu.Unlock()
	r.notify()
	return true
}

func (r *readySession) notify() {
	w := r.s.n.io
	w.mu.Lock()
	defer w.mu.Unlock()
	if r.finished {
		return
	}
	if r.initializing || r.queued {
		r.again = true
		return
	}
	r.queued = true
	w.append(r)
}

func (w *udpWorkers) append(r *readySession) {
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

func (w *udpWorkers) run() {
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
			if r.again && !r.finished {
				w.append(r)
			} else {
				r.queued = false
			}
			w.mu.Unlock()
			runtime.Gosched()
		}
	}
}

func (r *readySession) finish() {
	s := r.s
	w := s.n.io
	w.mu.Lock()
	r.finished = true
	w.mu.Unlock()
	r.watch.Detach()
	s.close()
	r.socket.Close()
	if r.pending != nil {
		s.n.control.ReleasePending(r.pending.bytes)
		r.pending = nil
	}
	s.ticket.Close()
	s.n.wg.Done()
}

func (r *readySession) step() {
	s, n := r.s, r.s.n
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed || n.ctx.Err() != nil {
		r.finish()
		return
	}
	blocked := false
	for range 32 {
		s.mu.Lock()
		if r.pending == nil && len(s.queue) != 0 {
			d := s.queue[0]
			s.queue[0] = datagram{}
			s.queue = s.queue[1:]
			s.bytes -= d.bytes
			r.pending = &d
		}
		fresh := !s.closed && n.now().Sub(s.validated) < IdentityMaxAge
		app := s.owner.AppID
		s.mu.Unlock()
		if r.pending == nil {
			break
		}
		d := r.pending
		if fresh {
			written, err := r.socket.TryWriteTo(d.payload, d.destination, d.df)
			if errors.Is(err, platform.ErrWouldBlock) {
				blocked = true
				break
			}
			if err == nil {
				s.ticket.Add(uint64(written), 0)
				s.mu.Lock()
				s.last = n.now()
				s.mu.Unlock()
			} else if errors.Is(err, platform.ErrDatagramDropped) {
				n.Dropped.Add(1)
			} else if n.control.AllowReject(app) {
				var big *platform.TooBig
				var mtu uint32
				if errors.As(err, &big) {
					mtu = big.MTU
				}
				n.out.Send(packet.Unreachable(d.original, mtu))
			}
		} else {
			n.Dropped.Add(1)
		}
		n.control.ReleasePending(d.bytes)
		r.pending = nil
	}
	for i := 0; i < 32 && !time.Now().Before(r.readAfter); i++ {
		reply, err := s.readAvailable(r.socket.TryReadFrom)
		if errors.Is(err, platform.ErrWouldBlock) {
			r.backoff = 0
			break
		}
		if errors.Is(err, net.ErrClosed) {
			r.finish()
			return
		}
		if err != nil {
			switch {
			case errors.Is(err, errReplyBudget):
				n.Dropped.Add(1)
			case platform.IsTooBig(err):
				n.Oversize.Add(1)
			default:
				n.ReadErrors.Add(1)
			}
			r.backoff = min(100*time.Millisecond, max(time.Millisecond, r.backoff*2))
			r.readAfter = time.Now().Add(r.backoff)
			time.AfterFunc(r.backoff, r.notify)
			break
		}
		r.backoff = 0
		s.mu.Lock()
		fresh := !s.closed && n.now().Sub(s.validated) < IdentityMaxAge
		s.mu.Unlock()
		if !fresh {
			reply.release()
			n.Dropped.Add(1)
		} else if n.out.SendBatch(reply.packets, reply.release) {
			s.ticket.Add(0, uint64(reply.size))
			s.mu.Lock()
			s.last = n.now()
			s.mu.Unlock()
		} else {
			n.Dropped.Add(1)
		}
	}
	if err := r.watch.Arm(!time.Now().Before(r.readAfter), blocked); err != nil {
		r.finish()
		return
	}
	s.mu.Lock()
	more := len(s.queue) != 0 || s.closed
	s.mu.Unlock()
	if more && !blocked {
		r.notify()
	}
}
