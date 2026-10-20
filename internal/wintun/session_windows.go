//go:build windows

package wintun

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AyoubAchour/net-switch/internal/winclock"
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
	ReadWaits        uint64
	ReadWakes        uint64
	Placeholders     uint64
	OversizedPackets uint64
	CloseNanos       uint64
	CloseDetails     CloseDetails
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
	readWaits, readWakes              atomic.Uint64
	placeholders, oversized           atomic.Uint64
	closeStarted                      atomic.Int64
	closeNanos                        atomic.Uint64
	closeDetails                      atomic.Pointer[CloseDetails]
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

// RXChecksumVerified is called only for an unmodified packet returned by Read.
// validIP already checked TCP/UDP and the IPv4 header. Keep stack verification
// for fragments, ICMP, and all other protocols, including unknown extensions.
func (*Session) RXChecksumVerified(p []byte) bool {
	if len(p) >= 20 && p[0]>>4 == 4 {
		return binary.BigEndian.Uint16(p[6:8])&0x3fff == 0 && (p[9] == 6 || p[9] == 17)
	}
	if len(p) >= 40 && p[0]>>4 == 6 {
		protocol, body := p[6], p[40:]
		for protocol == 0 || protocol == 43 || protocol == 60 {
			if len(body) < 8 {
				return false
			}
			n := (int(body[1]) + 1) * 8
			if n > len(body) {
				return false
			}
			protocol, body = body[0], body[n:]
		}
		return protocol == 6 || protocol == 17
	}
	return false
}
func (s *Session) Stats() Stats {
	result := Stats{ReadPackets: s.read.Load(), WrittenPackets: s.written.Load(), DroppedPackets: s.dropped.Load(), Corruptions: s.corruptions.Load(), Recoveries: s.recoveries.Load(), RecoveryFailures: s.failures.Load(), Wakeups: s.wakeups.Load(), ReadWaits: s.readWaits.Load(), ReadWakes: s.readWakes.Load(), Placeholders: s.placeholders.Load(), OversizedPackets: s.oversized.Load(), CloseNanos: s.closeNanos.Load()}
	if details := s.closeDetails.Load(); details != nil {
		result.CloseDetails = *details
	}
	return result
}

// fail is called with mu held. Recovery runs elsewhere so neither a full ring
// nor a damaged ring can make a stack writer wait for PnP or driver teardown.
func (s *Session) fail(err error) {
	if s.closed.Load() || s.err != nil || !s.recovering.CompareAndSwap(false, true) {
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
	defer func() {
		s.closeNanos.Store(uint64(winclock.Since(time.Duration(s.closeStarted.Load()))))
		close(s.stopped)
	}()
	defer close(s.events)
	var lastLog time.Time
	var lastRecovery time.Time
	var delay time.Duration
	for {
		select {
		case <-s.stop:
			// The read mutex also covers cancellation callback completion.
			// Close has already signalled wake, so an active native wait exits.
			started := winclock.Now()
			queued := uint64(started - time.Duration(s.closeStarted.Load()))
			s.readMu.Lock()
			readLock := uint64(winclock.Since(started))
			started = winclock.Now()
			s.mu.Lock()
			stateLock := uint64(winclock.Since(started))
			var profile CloseDetails
			if s.rings != nil {
				s.closeErr = s.rings.close()
				profile = s.rings.closeProfile
				s.rings = nil
			}
			started = winclock.Now()
			s.closeErr = errors.Join(s.closeErr, windows.CloseHandle(s.wake), windows.CloseHandle(s.cancelEvent))
			profile.EventsNanos += uint64(winclock.Since(started))
			profile.QueueNanos, profile.ReadLockNanos, profile.StateLockNanos = queued, readLock, stateLock
			s.closeDetails.Store(&profile)
			close(s.changed)
			s.mu.Unlock()
			s.readMu.Unlock()
			return
		case cause := <-s.repair:
			if errors.Is(cause, ErrCorrupt) {
				if time.Since(lastRecovery) < 10*time.Second {
					delay = min(max(delay*2, 10*time.Millisecond), 250*time.Millisecond)
				} else {
					delay = 0
				}
				if err := waitRetry(s.stop, delay); err != nil {
					continue
				}
				lastRecovery = time.Now()
			}
			s.mu.Lock()
			if s.closed.Load() {
				s.mu.Unlock()
				continue
			}
			err := s.rings.close()
			s.rings = nil
			removed := errors.Is(cause, ErrDisconnected)
			if !removed && err == nil {
				s.event("recovering", cause)
				s.rings, err = reopenRings(s.stop, func() (*rings, error) {
					return openRings(s.adapter.devicePath, s.adapter.config.Capacity)
				})
				removed = errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) || errors.Is(err, windows.ERROR_DEVICE_NOT_CONNECTED)
			}
			if removed {
				s.err = errors.Join(ErrAdapterRemoved, err)
				s.event("removed", s.err)
				slog.Info("Wintun adapter removed", "adapter", s.adapter.config.Name, "error", err)
			} else if err != nil {
				s.failures.Add(1)
				s.err = fmt.Errorf("Wintun session recovery after %v: %w", cause, err)
				s.event("failed", s.err)
				slog.Error("Wintun session recovery failed", "adapter", s.adapter.config.Name, "error", s.err)
			} else {
				s.recoveries.Add(1)
				s.event("recovered", nil)
				if time.Since(lastLog) >= 10*time.Second {
					slog.Warn("Wintun ring corruption recovered", "adapter", s.adapter.config.Name, "error", cause, "corruptions", s.corruptions.Load())
					lastLog = time.Now()
				}
			}
			s.recovering.Store(false)
			windows.ResetEvent(s.wake)
			close(s.changed)
			s.changed = make(chan struct{})
			s.mu.Unlock()
		}
	}
}

func waitRetry(stop <-chan struct{}, delay time.Duration) error {
	if !winclock.System.WaitDone(stop, delay) {
		return net.ErrClosed
	}
	return nil
}

// 0.14.1 returns STATUS_ALREADY_INITIALIZED while removal owns RegistrationLock.
// Retry only that transient result, with a bound and interruptible backoff.
func reopenRings(stop <-chan struct{}, open func() (*rings, error)) (*rings, error) {
	for attempt := 0; ; attempt++ {
		r, err := open()
		if !errors.Is(err, windows.ERROR_ALREADY_INITIALIZED) || attempt == 6 {
			return r, err
		}
		if err := waitRetry(stop, (10*time.Millisecond)<<attempt); err != nil {
			return nil, err
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
	if errors.Is(err, ErrDisconnected) {
		err = ErrAdapterRemoved
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
		r := s.rings
		placeholders, oversized := r.placeholders, r.oversized
		n, err := r.read(buffers, sizes)
		if dropped := r.placeholders - placeholders; dropped != 0 {
			s.placeholders.Add(dropped)
			s.dropped.Add(dropped)
		}
		if dropped := r.oversized - oversized; dropped != 0 {
			s.oversized.Add(dropped)
			s.dropped.Add(dropped)
		}
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
		// A ready batch needs no native wait or cancellation callback allocation.
		// Install the callback only when parking, and join it before readMu is
		// released so Close can safely destroy the event.
		if cancelEvent == 0 && ctx.Done() != nil {
			event := s.cancelEvent
			cancelEvent = event
			finished := make(chan struct{})
			stop := context.AfterFunc(ctx, func() { windows.SetEvent(event); close(finished) })
			defer func() {
				if !stop() {
					<-finished
					windows.ResetEvent(event)
				}
			}()
		}
		handles := []windows.Handle{s.wake, s.rings.readEvent}
		if cancelEvent != 0 {
			handles = append(handles, cancelEvent)
		}
		s.readWaits.Add(1)
		_, err = windows.WaitForMultipleObjects(handles, false, windows.INFINITE)
		if err == nil {
			s.readWakes.Add(1)
		}
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

// BeginClose interrupts packet I/O immediately and starts native teardown.
// The owner must still call Close to join teardown and receive its result.
func (s *Session) BeginClose() {
	s.closeOnce.Do(func() {
		s.closeStarted.Store(int64(winclock.Now()))
		s.closed.Store(true)
		// Close cannot wait for mu before signalling: a reader may be holding
		// a read lock inside WaitForMultipleObjects.
		windows.SetEvent(s.wake)
		close(s.stop)
	})
}

func (s *Session) Close() error {
	s.BeginClose()
	<-s.stopped
	return s.closeErr
}
