//go:build windows

package winengine

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/winclock"
	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"github.com/AyoubAchour/net-switch/internal/winwait"
	"golang.org/x/sys/windows"
)

// WSAEventSelect and WSAPoll are documented on our Windows 10 19045 floor.
// Each event covers at most 256 sockets. Two waiters each watch 32 shard
// events and one stop event; no socket owns a waiter, receive buffer or event.
// ProcessSocketNotifications needs build 20348, so it cannot be our baseline.
const udpShardCount, udpShardCapacity, udpWaiters = 64, 256, 2

var udpEventSelectProc = winsock.NewProc("WSAEventSelect")
var udpPollProc = winsock.NewProc("WSAPoll")

type udpReadinessFailure struct{ err error }

type udpReadiness struct {
	mu       sync.Mutex // registration allocation only; never acquired by Arm or polling
	closeMu  sync.Mutex
	shards   [udpShardCount]udpShard
	stops    [udpWaiters]winhandle.Owner
	next     int
	closed   atomic.Bool
	failure  atomic.Pointer[udpReadinessFailure]
	wg       sync.WaitGroup
	closeErr error
	onError  func(error)
	capture  bool
	poll     func([]pollFD) (int32, error)
	// waits holds each waiter's native wait array, written only by that
	// waiter. It lives in this heap object so no stack copy can move it
	// under the kernel.
	waits [udpWaiters][udpShardCount/udpWaiters + 1]windows.Handle
}

type udpShard struct {
	mu      sync.Mutex // fences native queries and unregister-before-close
	event   winhandle.Owner
	watches map[*udpWatch]struct{}
	metrics udpReadinessMetrics
}

type udpWatch struct {
	pool     *udpReadiness
	shard    *udpShard
	socket   winhandle.Owner
	wake     func()
	events   int16
	detached bool
	err      error
}

func newUDPReadiness(onError func(error)) (*udpReadiness, error) {
	p := &udpReadiness{onError: onError, capture: hostedTraceEnabled(), poll: pollUDP}
	var opened []winhandle.Owner
	open := func(site string) (winhandle.Owner, error) {
		h, err := windows.CreateEvent(nil, 1, 0, nil)
		if err != nil {
			return winhandle.Owner{}, err
		}
		owner := winhandle.Open(h, site)
		opened = append(opened, owner)
		return owner, nil
	}
	var err error
	for i := range p.stops {
		p.stops[i], err = open("UDP readiness waiter stop open")
		if err != nil {
			break
		}
	}
	if err == nil {
		for i := range p.shards {
			s := &p.shards[i]
			s.event, err = open(fmt.Sprintf("UDP readiness shard %d event open", i))
			if err != nil {
				break
			}
			s.watches = make(map[*udpWatch]struct{})
		}
	}
	if err != nil {
		for _, owner := range opened {
			err = errors.Join(err, owner.HandleClose("UDP readiness setup failure close"))
		}
		return nil, err
	}
	p.wg.Add(udpWaiters)
	for i := range udpWaiters {
		go p.run(i)
	}
	return p, nil
}

func selectUDPEvents(socket winhandle.Owner, event windows.Handle, mask int32) error {
	code, _, err := udpEventSelectProc.Call(uintptr(socket.Handle("UDP event selection")), uintptr(event), uintptr(mask))
	if int32(code) == -1 {
		return err
	}
	return nil
}

func pollUDP(rows []pollFD) (int32, error) {
	n, _, err := udpPollProc.Call(uintptr(unsafe.Pointer(&rows[0])), uintptr(len(rows)), 0)
	if int32(n) == -1 {
		return -1, err
	}
	return int32(n), nil
}

func (p *udpReadiness) watch(socket winhandle.Owner, wake func()) (*udpWatch, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed.Load() {
		return nil, net.ErrClosed
	}
	if failure := p.failure.Load(); failure != nil {
		return nil, failure.err
	}
	for offset := range udpShardCount {
		index := (p.next + offset) % udpShardCount
		s := &p.shards[index]
		s.mu.Lock()
		if len(s.watches) < udpShardCapacity {
			w := &udpWatch{pool: p, shard: s, socket: socket, wake: wake}
			s.watches[w] = struct{}{}
			s.mu.Unlock()
			p.next = (index + 1) % udpShardCount
			return w, nil
		}
		s.mu.Unlock()
	}
	return nil, fmt.Errorf("Windows UDP readiness reached its %d socket ceiling", udpShardCount*udpShardCapacity)
}

func (w *udpWatch) Arm(read, write bool) error {
	p, s := w.pool, w.shard
	var began time.Duration
	if p.capture {
		began = winclock.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.capture {
		s.metrics.ArmLockWait.add(winclock.Since(began))
		defer func() { s.metrics.Arm.add(winclock.Since(began)) }()
	}
	if w.detached || p.closed.Load() {
		return net.ErrClosed
	}
	if failure := p.failure.Load(); failure != nil {
		return failure.err
	}
	if w.err != nil {
		return w.err
	}
	var mask int32
	var events int16
	if read {
		mask |= 1
		events |= 0x100
	}
	if write {
		mask |= 2
		events |= 0x10
	}
	// Replacing the mask clears this socket's record. Always query its shard
	// after rearm, including FD_WRITE: rearm is level-triggered, not an edge wait.
	if err := selectUDPEvents(w.socket, s.event.Handle("UDP shard event arm"), mask); err != nil {
		return err
	}
	w.events = events
	if events != 0 {
		if p.capture {
			s.metrics.SetEvents++
		}
		return windows.SetEvent(s.event.Handle("UDP shard arm wake"))
	}
	return nil
}

func (w *udpWatch) Detach() {
	s := w.shard
	s.mu.Lock()
	defer s.mu.Unlock()
	if w.detached {
		return
	}
	w.detached, w.events = true, 0
	w.err = selectUDPEvents(w.socket, 0, 0)
	delete(s.watches, w)
}

func (p *udpReadiness) fail(err error) {
	if !p.failure.CompareAndSwap(nil, &udpReadinessFailure{err}) {
		return
	}
	for _, stop := range p.stops {
		windows.SetEvent(stop.Handle("UDP failure wake"))
	}
	// A failed waiter ends readiness for the whole pool. Wake every armed
	// mapping, including those owned by the other waiter, before reporting the
	// fatal error. Callbacks only schedule work and run outside the shard lock.
	for i := range p.shards {
		s := &p.shards[i]
		callbacks := make([]func(), 0, udpShardCapacity)
		s.mu.Lock()
		for w := range s.watches {
			if w.events == 0 {
				continue
			}
			w.events = 0
			w.err = errors.Join(err, selectUDPEvents(w.socket, 0, 0))
			callbacks = append(callbacks, w.wake)
		}
		s.mu.Unlock()
		for _, callback := range callbacks {
			callback()
		}
	}
	if p.onError != nil {
		p.onError(err)
	}
}

func (p *udpReadiness) run(worker int) {
	defer p.wg.Done()
	const perWaiter = udpShardCount / udpWaiters
	handles := &p.waits[worker]
	var events [perWaiter]windows.Handle
	// These values remain owned until both waiters have joined in close().
	handles[0] = p.stops[worker].Handle("UDP waiter stop")
	for i := range perWaiter {
		events[i] = p.shards[i*udpWaiters+worker].event.Handle("UDP waiter shard event")
	}
	rows := make([]pollFD, 0, udpShardCapacity)
	watches := make([]*udpWatch, 0, udpShardCapacity)
	callbacks := make([]func(), 0, udpShardCapacity)
	cursor := 0
	for {
		for i := range perWaiter {
			handles[i+1] = events[(cursor+i)%perWaiter]
		}
		result, err := winwait.WaitForMultipleObjects(handles[:], false, windows.INFINITE)
		if err != nil {
			p.fail(fmt.Errorf("UDP readiness waiter %d wait (stop %#x and %d shard events %#x): %w", worker, handles[0], perWaiter, handles[1:], err))
			return
		}
		if result == windows.WAIT_OBJECT_0 {
			return
		}
		if result < windows.WAIT_OBJECT_0+1 || result > windows.WAIT_OBJECT_0+perWaiter {
			p.fail(fmt.Errorf("unexpected UDP wait result %d", result))
			return
		}
		slot := int(result-windows.WAIT_OBJECT_0) - 1
		index := ((cursor+slot)%perWaiter)*udpWaiters + worker
		// WaitForMultipleObjects favors the lowest signalled index. Rotation
		// plus one bounded poll per turn prevents a hot shard starving another.
		cursor = (cursor + slot + 1) % perWaiter
		s := &p.shards[index]
		s.mu.Lock()
		if p.closed.Load() {
			s.mu.Unlock()
			return
		}
		err = windows.ResetEvent(s.event.Handle("UDP shard event reset"))
		var began time.Duration
		if p.capture {
			s.metrics.WaitReturns++
			began = winclock.Now()
		}
		rows, watches, callbacks = rows[:0], watches[:0], callbacks[:0]
		for w := range s.watches {
			if w.events != 0 {
				rows = append(rows, pollFD{Socket: w.socket.Handle("UDP shard readiness poll"), Events: w.events})
				watches = append(watches, w)
			}
		}
		if p.capture {
			s.metrics.BuildRows.add(winclock.Since(began))
			began = winclock.Now()
		}
		if len(rows) != 0 && err == nil {
			n, callErr := p.poll(rows)
			if p.capture {
				s.metrics.Poll.add(winclock.Since(began))
				s.metrics.PollRows += uint64(len(rows))
				s.metrics.MaxPollRows = max(s.metrics.MaxPollRows, uint64(len(rows)))
				if n == 0 {
					s.metrics.ZeroReadyPolls++
				}
			}
			if n == -1 {
				err = callErr
			}
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
			s.metrics.ReadyRows += uint64(len(callbacks))
			s.metrics.Disarm.add(winclock.Since(began))
		}
		s.mu.Unlock()
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
			s.mu.Lock()
			s.metrics.Callbacks.add(elapsed)
			s.mu.Unlock()
		}
		if err != nil {
			p.fail(err)
			return
		}
	}
}

func (p *udpReadiness) close() error {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	if p.closed.Load() {
		return p.closeErr
	}
	p.mu.Lock()
	for i := range p.shards {
		s := &p.shards[i]
		s.mu.Lock()
		live := len(s.watches)
		s.mu.Unlock()
		if live != 0 {
			p.mu.Unlock()
			return errors.New("cannot close UDP readiness with live sockets")
		}
	}
	p.closed.Store(true)
	for _, stop := range p.stops {
		p.closeErr = errors.Join(p.closeErr, windows.SetEvent(stop.Handle("UDP waiter stop signal")))
	}
	p.mu.Unlock()
	p.wg.Wait()
	if failure := p.failure.Load(); failure != nil {
		p.closeErr = errors.Join(p.closeErr, failure.err)
	}
	for i := range p.shards {
		p.closeErr = errors.Join(p.closeErr, p.shards[i].event.HandleClose("UDP shard event close"))
	}
	for _, stop := range p.stops {
		p.closeErr = errors.Join(p.closeErr, stop.HandleClose("UDP waiter stop close"))
	}
	return p.closeErr
}
