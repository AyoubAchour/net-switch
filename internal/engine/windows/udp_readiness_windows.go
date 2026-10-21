//go:build windows

package winengine

import (
	"errors"
	"net"
	"sync"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/winclock"
	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

// UDP uses documented event readiness, not an overlapped MSG_PEEK receive.
// One manual-reset event wakes a batched, non-consuming WSAPoll query. No
// socket owns a receive buffer, waiter goroutine or individual event handle.
// https://learn.microsoft.com/windows/win32/api/winsock2/nf-winsock2-wsaeventselect
// https://learn.microsoft.com/windows/win32/api/winsock2/nf-winsock2-wsapoll
type udpReadiness struct {
	mu      sync.Mutex
	event   winhandle.Owner
	watches map[*udpWatch]struct{}
	closed  bool
	err     error
	onError func(error)
	done    chan struct{}
	capture bool
	metrics udpReadinessMetrics
}

type udpWatch struct {
	pool     *udpReadiness
	socket   winhandle.Owner
	wake     func()
	events   int16
	detached bool
	err      error
}

func newUDPReadiness(onError func(error)) (*udpReadiness, error) {
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	p := &udpReadiness{event: winhandle.Open(event, "UDP readiness event open"), watches: map[*udpWatch]struct{}{}, done: make(chan struct{}), onError: onError, capture: hostedTraceEnabled()}
	go p.run()
	return p, nil
}

func selectUDPEvents(socket winhandle.Owner, event windows.Handle, mask int32) error {
	code, _, err := winsock.NewProc("WSAEventSelect").Call(uintptr(socket.Handle("UDP event selection")), uintptr(event), uintptr(mask))
	if int32(code) == -1 {
		return err
	}
	return nil
}

func (p *udpReadiness) watch(socket winhandle.Owner, wake func()) (*udpWatch, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, net.ErrClosed
	}
	if p.err != nil {
		return nil, p.err
	}
	w := &udpWatch{pool: p, socket: socket, wake: wake}
	p.watches[w] = struct{}{}
	return w, nil
}

func (w *udpWatch) Arm(read, write bool) error {
	p := w.pool
	var started time.Duration
	if p.capture {
		started = winclock.Now()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.capture {
		p.metrics.ArmLockWait.add(winclock.Since(started))
		defer func() { p.metrics.Arm.add(winclock.Since(started)) }()
	}
	if w.detached || p.closed {
		return net.ErrClosed
	}
	if p.err != nil {
		return p.err
	}
	if w.err != nil {
		return w.err
	}
	var mask int32
	var events int16
	if read {
		mask |= 1        // FD_READ.
		events |= 0x0100 // POLLRDNORM.
	}
	if write {
		mask |= 2        // FD_WRITE.
		events |= 0x0010 // POLLWRNORM.
	}
	// Replacing the event mask clears that socket's old event record. Windows
	// also records already-readable/writable state, closing the rearm race.
	if err := selectUDPEvents(w.socket, p.event.Handle("UDP event arm"), mask); err != nil {
		return err
	}
	w.events = events
	if events != 0 {
		// FD_WRITE is edge-triggered, and an unconnected UDP socket need not
		// have had a connect event. Query current state once on every arm;
		// later network changes wake the same event without a receive.
		if p.capture {
			p.metrics.SetEvents++
		}
		return windows.SetEvent(p.event.Handle("UDP arm wake"))
	}
	return nil
}

func (w *udpWatch) Detach() {
	p := w.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	if w.detached {
		return
	}
	w.detached = true
	w.events = 0
	// The same lock covers the nonblocking poll query, so no query can still
	// refer to this descriptor after Detach returns and Close recycles it.
	w.err = selectUDPEvents(w.socket, 0, 0)
	delete(p.watches, w)
}

func (p *udpReadiness) run() {
	defer close(p.done)
	var rows []pollFD
	var watches []*udpWatch
	var callbacks []func()
	for {
		_, waitErr := windows.WaitForSingleObject(p.event.Handle("UDP event wait"), windows.INFINITE)
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return
		}
		// Reset before querying readiness. Arrivals after this point leave the
		// event signalled for the next pass; those before it are in the query.
		resetErr := windows.ResetEvent(p.event.Handle("UDP event reset"))
		var began time.Duration
		if p.capture {
			p.metrics.WaitReturns++
			began = winclock.Now()
		}
		rows, watches, callbacks = rows[:0], watches[:0], callbacks[:0]
		for w := range p.watches {
			if w.events != 0 {
				rows = append(rows, pollFD{Socket: w.socket.Handle("UDP readiness poll"), Events: w.events})
				watches = append(watches, w)
			}
		}
		err := errors.Join(waitErr, resetErr)
		if p.capture {
			p.metrics.BuildRows.add(winclock.Since(began))
			began = winclock.Now()
		}
		if len(rows) > 0 && err == nil {
			n, _, callErr := winsock.NewProc("WSAPoll").Call(uintptr(unsafe.Pointer(&rows[0])), uintptr(len(rows)), 0)
			if p.capture {
				p.metrics.Poll.add(winclock.Since(began))
				p.metrics.PollRows += uint64(len(rows))
				p.metrics.MaxPollRows = max(p.metrics.MaxPollRows, uint64(len(rows)))
				if n == 0 {
					p.metrics.ZeroReadyPolls++
				}
			}
			if int32(n) == -1 {
				err = callErr
			}
		}
		if err != nil {
			p.err = err
		}
		if p.capture {
			began = winclock.Now()
		}
		for i, row := range rows {
			if row.Returned == 0 && err == nil {
				continue
			}
			w := watches[i]
			w.events = 0
			w.err = errors.Join(err, selectUDPEvents(w.socket, 0, 0))
			callbacks = append(callbacks, w.wake)
		}
		if p.capture {
			p.metrics.ReadyRows += uint64(len(callbacks))
			p.metrics.Disarm.add(winclock.Since(began))
		}
		p.mu.Unlock()
		// Detach may race these already-selected callbacks. The shared worker
		// ignores late scheduling after it finishes; callbacks do no socket I/O.
		if p.capture {
			began = winclock.Now()
		}
		for i, callback := range callbacks {
			callback()
			callbacks[i] = nil
		}
		clear(watches)
		if p.capture {
			elapsed := winclock.Since(began)
			p.mu.Lock()
			p.metrics.Callbacks.add(elapsed)
			p.mu.Unlock()
		}
		if err != nil {
			if p.onError != nil {
				p.onError(err)
			}
			return
		}
	}
}

func (p *udpReadiness) close() error {
	p.mu.Lock()
	if len(p.watches) != 0 {
		p.mu.Unlock()
		return errors.New("cannot close UDP readiness with live sockets")
	}
	p.closed = true
	windows.SetEvent(p.event.Handle("UDP readiness stop"))
	p.mu.Unlock()
	<-p.done
	return errors.Join(p.err, p.event.HandleClose("UDP readiness event close"))
}
