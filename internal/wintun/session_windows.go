//go:build windows

package wintun

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
)

// PacketSession is the batch boundary for the Windows link endpoint. Reads
// copy into caller-owned buffers; none of the driver's memory escapes.
// Writes return the accepted count. All other packets are dropped and counted.
type PacketSession interface {
	ReadBatch(context.Context, [][]byte, []int) (int, error)
	WriteBatch([][]byte) (int, error)
	MTU() int
	LUID() uint64
	Stats() Stats
	Events() <-chan Event
	Close() error
}

type Stats struct {
	ReadPackets      uint64
	WrittenPackets   uint64
	DroppedPackets   uint64
	Corruptions      uint64
	Recoveries       uint64
	RecoveryFailures uint64
	Wakeups          uint64
}

// Events are advisory and bounded. Stats remain authoritative if a caller
// does not drain this channel. A terminal read error is never hidden by it.
type Event struct {
	Kind string
	Err  error
}

type Session struct {
	adapter            *Adapter
	mu                 sync.RWMutex // keeps resources alive during native waits and packet copies
	readMu, writeMu    sync.Mutex
	rings              *rings
	wake, cancelEvent  windows.Handle
	changed            chan struct{}
	err, closeErr      error
	closed, recovering atomic.Bool
	closeOnce          sync.Once
	stop, stopped      chan struct{}
	repair             chan error
	events             chan Event

	read, written, dropped            atomic.Uint64
	corruptions, recoveries, failures atomic.Uint64
	wakeups                           atomic.Uint64
}

func (a *Adapter) StartSession() (*Session, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.handle == 0 {
		return nil, net.ErrClosed
	}
	if a.session != nil {
		select {
		case <-a.session.stopped:
		default:
			return nil, fmt.Errorf("adapter already has a session")
		}
	}
	r, err := openRings(a.devicePath, a.config.Capacity)
	if err != nil {
		return nil, err
	}
	wake, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, errors.Join(err, r.close())
	}
	cancelEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, errors.Join(err, windows.CloseHandle(wake), r.close())
	}
	s := &Session{adapter: a, rings: r, wake: wake, cancelEvent: cancelEvent, changed: make(chan struct{}), stop: make(chan struct{}), stopped: make(chan struct{}), repair: make(chan error, 1), events: make(chan Event, 8)}
	a.session = s
	go s.maintain()
	return s, nil
}

func (s *Session) MTU() int             { return s.adapter.MTU() }
func (s *Session) LUID() uint64         { return s.adapter.LUID() }
func (s *Session) Events() <-chan Event { return s.events }
func (s *Session) Stats() Stats {
	return Stats{s.read.Load(), s.written.Load(), s.dropped.Load(), s.corruptions.Load(), s.recoveries.Load(), s.failures.Load(), s.wakeups.Load()}
}

// fail is called with mu held. Recovery runs elsewhere so neither a full ring
// nor a damaged ring can make a stack writer wait for PnP or driver teardown.
func (s *Session) fail(err error) {
	if s.closed.Load() || !s.recovering.CompareAndSwap(false, true) {
		return
	}
	if errors.Is(err, ErrCorrupt) {
		s.corruptions.Add(1)
	}
	windows.SetEvent(s.wake)
	s.repair <- err
}

func (s *Session) event(kind string, err error) {
	select {
	case s.events <- Event{kind, err}:
	default:
	}
}

func (s *Session) maintain() {
	defer close(s.stopped)
	defer close(s.events)
	var lastLog time.Time
	for {
		select {
		case <-s.stop:
			// The read mutex also covers cancellation callback completion.
			// Close has already signalled wake, so an active native wait exits.
			s.readMu.Lock()
			s.mu.Lock()
			if s.rings != nil {
				s.closeErr = s.rings.close()
				s.rings = nil
			}
			s.closeErr = errors.Join(s.closeErr, windows.CloseHandle(s.wake), windows.CloseHandle(s.cancelEvent))
			close(s.changed)
			s.mu.Unlock()
			s.readMu.Unlock()
			return
		case cause := <-s.repair:
			s.mu.Lock()
			if s.closed.Load() {
				s.mu.Unlock()
				continue
			}
			if time.Since(lastLog) >= 10*time.Second {
				slog.Error("Wintun session stopped; reopening rings", "adapter", s.adapter.config.Name, "error", cause, "corruptions", s.corruptions.Load())
				lastLog = time.Now()
			}
			s.event("recovering", cause)
			err := s.rings.close()
			if err == nil {
				s.rings = nil
				s.rings, err = openRings(s.adapter.devicePath, s.adapter.config.Capacity)
			}
			if err != nil {
				s.failures.Add(1)
				s.err = fmt.Errorf("Wintun session recovery after %v: %w", cause, err)
				s.event("failed", s.err)
				slog.Error("Wintun session recovery failed", "adapter", s.adapter.config.Name, "error", s.err)
			} else {
				s.recoveries.Add(1)
				s.event("recovered", nil)
			}
			s.recovering.Store(false)
			windows.ResetEvent(s.wake)
			close(s.changed)
			s.changed = make(chan struct{})
			s.mu.Unlock()
		}
	}
}

func (s *Session) WriteBatch(packets [][]byte) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	if !s.writeMu.TryLock() {
		s.dropped.Add(uint64(len(packets)))
		return 0, nil
	}
	defer s.writeMu.Unlock()
	if !s.mu.TryRLock() {
		s.dropped.Add(uint64(len(packets)))
		return 0, nil
	}
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	if s.err != nil {
		s.dropped.Add(uint64(len(packets)))
		return 0, s.err
	}
	if s.recovering.Load() {
		s.dropped.Add(uint64(len(packets)))
		return 0, nil
	}
	n, drops, err := s.rings.write(packets)
	s.written.Add(uint64(n))
	s.dropped.Add(uint64(drops))
	if n != 0 {
		s.wakeups.Add(1)
	}
	if err != nil {
		s.fail(err)
	}
	return n, err
}

// ReadBatch has one ordered reader. A blocking read is interrupted by Close,
// recovery, adapter removal, or context cancellation. Empty batches are errors.
func (s *Session) ReadBatch(ctx context.Context, buffers [][]byte, sizes []int) (int, error) {
	if len(buffers) == 0 || len(sizes) < len(buffers) {
		return 0, fmt.Errorf("invalid read batch")
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	var cancelEvent windows.Handle
	if ctx.Done() != nil {
		cancelEvent = s.cancelEvent
		finished := make(chan struct{})
		stop := context.AfterFunc(ctx, func() { windows.SetEvent(cancelEvent); close(finished) })
		defer func() {
			if !stop() {
				<-finished
				windows.ResetEvent(cancelEvent)
			}
		}()
	}
	spins := 0
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		s.mu.RLock()
		if s.closed.Load() {
			s.mu.RUnlock()
			return 0, net.ErrClosed
		}
		if s.err != nil {
			err := s.err
			s.mu.RUnlock()
			return 0, err
		}
		if s.recovering.Load() {
			changed := s.changed
			s.mu.RUnlock()
			select {
			case <-changed:
			case <-s.stop:
				return 0, net.ErrClosed
			case <-ctx.Done():
				return 0, ctx.Err()
			}
			continue
		}
		n, err := s.rings.read(buffers, sizes)
		if errors.Is(err, ErrCorrupt) || errors.Is(err, ErrDisconnected) {
			s.fail(err)
			// Valid packets preceding the damaged entry remain ordered.
			if n == 0 {
				s.mu.RUnlock()
				continue
			}
			err = nil
		}
		if n != 0 || err != nil {
			s.read.Add(uint64(n))
			s.mu.RUnlock()
			return n, err
		}
		if spins < 8 {
			spins++
			s.mu.RUnlock()
			// Poll briefly, then park in the native wait below. Gosched here
			// schedules unrelated Go work rather than yielding to the driver,
			// adding eight scheduler round trips to a sparse packet stream.
			continue
		}
		// 0.14.1 TunSendNetBufferLists signals Send.TailMoved every time it
		// publishes Tail. Send.Alertable is unused. Never reset this event:
		// a signal between the empty check and Wait must remain pending.
		handles := []windows.Handle{s.wake, s.rings.readEvent}
		if cancelEvent != 0 {
			handles = append(handles, cancelEvent)
		}
		_, err = windows.WaitForMultipleObjects(handles, false, windows.INFINITE)
		s.mu.RUnlock()
		if err != nil {
			return 0, err
		}
		spins = 0
	}
}

func (s *Session) ReadPacket(ctx context.Context, buffer []byte) (int, error) {
	var sizes [1]int
	n, err := s.ReadBatch(ctx, [][]byte{buffer}, sizes[:])
	if n == 0 {
		return 0, err
	}
	return sizes[0], err
}

func (s *Session) WritePacket(ctx context.Context, packet []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := s.WriteBatch([][]byte{packet})
	return err
}

func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		// Close cannot wait for mu before signalling: a reader may be holding
		// a read lock inside WaitForMultipleObjects.
		windows.SetEvent(s.wake)
		close(s.stop)
	})
	<-s.stopped
	return s.closeErr
}
