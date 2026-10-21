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

	"github.com/AyoubAchour/net-switch/internal/platform/winapi"
	"github.com/AyoubAchour/net-switch/internal/winclock"
	"github.com/AyoubAchour/net-switch/internal/winhandle"
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
	Registrar        RegistrarStats
	Rings            *RingState `json:",omitempty"` // absent without live rings, or while they are being replaced
}

// RingState is a live read of both ring headers, for failure capture. The
// Send ring carries packets from Windows to the engine (the driver moves
// Tail, the engine Head); the Receive ring the reverse. Equal Head and Tail
// mean empty; a Head that does not move with a growing Tail means that side
// stopped consuming.
type RingState struct {
	Capacity                                   uint32
	SendHead, SendTail, SendAlertable          uint32
	ReceiveHead, ReceiveTail, ReceiveAlertable uint32
	// Registrar exit handle state: "running", "exited", or "none" for
	// fixtures without a registration owner.
	Registrar string
}

// Events are advisory and bounded. Stats remain authoritative if a caller
// does not drain this channel. A terminal read error is never hidden by it.
type Event struct {
	Kind string
	Err  error
}

type Session struct {
	adapter                *Adapter
	mu                     sync.RWMutex // keeps resources alive during native waits and packet copies
	readMu, writeMu        sync.Mutex
	rings                  *rings
	wake, cancelEvent      windows.Handle
	wakeOwner, cancelOwner winhandle.Owner
	changed                chan struct{}
	err, closeErr          error
	closed, recovering     atomic.Bool
	closeOnce              sync.Once
	stop, stopped          chan struct{}
	repair                 chan error
	events                 chan Event
	open                   func() (*rings, error)
	registrars             atomic.Uint64
	registrar              atomic.Pointer[RegistrarStats]
	// waitHandles is the reader's native wait array, guarded by readMu. It
	// lives in this heap object so no stack copy can move it under the kernel.
	waitHandles [4]windows.Handle

	read, written, dropped            atomic.Uint64
	corruptions, recoveries, failures atomic.Uint64
	wakeups                           atomic.Uint64
	readWaits, readWakes              atomic.Uint64
	placeholders, oversized           atomic.Uint64
	closeStarted                      atomic.Int64
	closeNanos                        atomic.Uint64
	closeDetails                      atomic.Pointer[CloseDetails]
}

// StartSession registers rings through a registrar process. There is no
// in-process registration path in production code, and no fallback to one.
func (a *Adapter) StartSession() (*Session, error) {
	return a.startSession(func() (*rings, error) { return openRings(a.devicePath, a.config.Capacity) })
}

// startSession takes the ring opener for both the first registration and
// recovery. Only tests pass anything other than StartSession's opener.
func (a *Adapter) startSession(open func() (*rings, error)) (*Session, error) {
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
	r, err := open()
	if err != nil {
		return nil, err
	}
	wake, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, errors.Join(err, r.close())
	}
	wakeOwner := winhandle.Open(wake, "Wintun session wake open")
	cancelEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, errors.Join(err, wakeOwner.HandleClose("Wintun session setup failure close"), r.close())
	}
	s := &Session{adapter: a, rings: r, wake: wake, cancelEvent: cancelEvent, changed: make(chan struct{}), stop: make(chan struct{}), stopped: make(chan struct{}), repair: make(chan error, 1), events: make(chan Event, 8), open: open}
	s.wakeOwner, s.cancelOwner = wakeOwner, winhandle.Open(cancelEvent, "Wintun cancellation event open")
	s.noteRings(r)
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
	if registrar := s.registrar.Load(); registrar != nil {
		result.Registrar = *registrar
	}
	// Never wait: close and recovery hold mu for driver teardown, and stats
	// must answer during exactly those moments.
	if s.mu.TryRLock() {
		if r := s.rings; r != nil && !r.closed {
			state := RingState{Capacity: r.send.capacity, Registrar: "none",
				SendHead: r.send.load(0), SendTail: r.send.load(4), SendAlertable: r.send.load(8),
				ReceiveHead: r.receive.load(0), ReceiveTail: r.receive.load(4), ReceiveAlertable: r.receive.load(8)}
			if h := r.exited(); h != 0 {
				state.Registrar = "running"
				if event, err := windows.WaitForSingleObject(h, 0); err != nil || event != uint32(windows.WAIT_TIMEOUT) {
					state.Registrar = "exited"
				}
			}
			result.Rings = &state
		}
		s.mu.RUnlock()
	}
	return result
}

func (s *Session) noteRings(r *rings) {
	if g, ok := r.owner.(*registrar); ok {
		stats := g.stats(s.registrars.Add(1))
		s.registrar.Store(&stats)
	}
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
	windows.SetEvent(s.wakeOwner.Handle("Wintun recovery wake"))
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
				s.closeErr = errors.Join(s.closeErr, s.rings.close())
				profile = s.rings.closeProfile
				s.rings = nil
			}
			started = winclock.Now()
			s.closeErr = errors.Join(s.closeErr, s.wakeOwner.HandleClose("Wintun session wake close"), s.cancelOwner.HandleClose("Wintun cancellation event close"))
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
			// Sample the driver's markers before retiring the owner, because its
			// stop makes the driver publish them as well. A marker already present
			// is a loss the driver published before our stop, which read and write
			// already treat as ErrDisconnected (removal, the owner's own exit that
			// end() classifies, or a receive-thread rejection). So the session is
			// lost even if ErrCorrupt queued this repair and the owner then exits
			// cleanly on our stop request.
			releasedFirst := s.rings.disconnected()
			err := s.rings.close()
			// The teardown/retirement error is a real cleanup failure, distinct
			// from the expected removal/owner-exit cause. Session.Close must still
			// surface it even though these rings are gone before the stop handler
			// runs; the cause itself is never treated as a cleanup failure.
			s.closeErr = errors.Join(s.closeErr, err)
			// end() recorded, from the joined registrar, whether its process had
			// already ended other than by our stop. A confirmed owner loss takes
			// precedence over a queued corruption cause: the session is lost and
			// must never be rebuilt in place, even if ErrCorrupt triggered this.
			lostToExit := s.rings.ownerExitedFirst
			s.rings = nil
			removed := errors.Is(cause, ErrDisconnected) || releasedFirst || lostToExit
			if !removed && err == nil {
				s.event("recovering", cause)
				s.rings, err = reopenRings(s.stop, s.open)
				removed = errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) || errors.Is(err, windows.ERROR_DEVICE_NOT_CONNECTED)
				if err == nil {
					s.noteRings(s.rings)
				}
			}
			if removed && lostToExit {
				// The registration owner exited on its own: a distinct reason from
				// adapter removal, the same session loss, and never a rebuild. The
				// teardown error (if any) is a cleanup failure kept in closeErr, not
				// part of this terminal reason.
				s.err = errors.Join(ErrAdapterRemoved, ErrRegistrarExited, cause)
				s.event("removed", s.err)
				slog.Warn("Wintun registration owner exited; session lost", "adapter", s.adapter.config.Name, "markersBeforeStop", releasedFirst, "error", errors.Join(s.err, err))
			} else if removed {
				s.err = errors.Join(ErrAdapterRemoved, cause)
				s.event("removed", s.err)
				slog.Info("Wintun adapter removed", "adapter", s.adapter.config.Name, "markersBeforeStop", releasedFirst, "error", errors.Join(s.err, err))
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
			windows.ResetEvent(s.wakeOwner.Handle("Wintun recovery reset"))
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
		err = s.writeLoss()
	}
	return n, err
}

// writeLoss is the writer's own adapter-lost error, decided without waiting
// and only on this loss path. The writer holds mu, so maintenance cannot be
// retiring the owner: an exit handle already signalled means it ended on its
// own. The driver publishes its markers from the owner's exit callback before
// the process is signalled, so a writer can see them first and report removal
// only; ReadBatch and later writes return maintenance's completed-exit reason.
func (s *Session) writeLoss() error {
	if h := s.rings.exited(); h != 0 {
		if event, err := windows.WaitForSingleObject(h, 0); err == nil && event == windows.WAIT_OBJECT_0 {
			return errors.Join(ErrAdapterRemoved, ErrRegistrarExited)
		}
	}
	return ErrAdapterRemoved
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
			event := s.cancelOwner.Handle("Wintun read cancellation")
			cancelEvent = event
			finished := make(chan struct{})
			stop := context.AfterFunc(ctx, func() { windows.SetEvent(s.cancelOwner.Handle("Wintun cancellation callback")); close(finished) })
			defer func() {
				if !stop() {
					<-finished
					windows.ResetEvent(s.cancelOwner.Handle("Wintun cancellation reset"))
				}
			}()
		}
		handles := s.waitHandles[:0]
		handles = append(handles, s.wakeOwner.Handle("Wintun read wake"), s.rings.readHandle())
		// A registrar that ends for any reason (crash, job termination) loses the
		// registration; wake a parked reader now instead of waiting for traffic.
		// The reason (owner exit vs adapter removal) is settled during teardown.
		exitIdx := -1
		if h := s.rings.exited(); h != 0 {
			exitIdx = len(handles)
			handles = append(handles, h)
		}
		cancelIdx := -1
		if cancelEvent != 0 {
			cancelIdx = len(handles)
			handles = append(handles, s.cancelOwner.Handle("Wintun cancellation wait"))
		}
		s.readWaits.Add(1)
		event, err := winapi.WaitForMultipleObjects(handles, false, windows.INFINITE)
		if err != nil {
			err = fmt.Errorf("Wintun read wait (wake %#x, read event %#x, registrar exit %#x, cancel %#x): %w",
				handles[0], handles[1], waitRole(handles, exitIdx), waitRole(handles, cancelIdx), err)
		}
		if err == nil {
			s.readWakes.Add(1)
		}
		if err == nil && exitIdx >= 0 && event == windows.WAIT_OBJECT_0+uint32(exitIdx) {
			s.fail(errOwnerLost)
		}
		s.mu.RUnlock()
		if err != nil {
			return 0, err
		}
		spins = 0
	}
}

// waitRole returns the handle at i for an error message, or zero when that
// role was not part of this wait.
func waitRole(handles []windows.Handle, i int) windows.Handle {
	if i < 0 || i >= len(handles) {
		return 0
	}
	return handles[i]
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
		windows.SetEvent(s.wakeOwner.Handle("Wintun close wake"))
		close(s.stop)
	})
}

func (s *Session) Close() error {
	s.BeginClose()
	<-s.stopped
	return s.closeErr
}
