//go:build windows

package wintun

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

var errTestRetire = errors.New("test retirement failure")

// faultyOwner reports a teardown error from end, like a failed registrar
// retirement (a CloseHandle failure or errRegistrarAlive), without a device.
type faultyOwner struct{ lost bool }

func (*faultyOwner) exited() windows.Handle { return 0 }
func (o *faultyOwner) end(r *rings, _ func(windows.Handle) error) (bool, error) {
	r.ownerExitedFirst = o.lost
	return false, errTestRetire
}

// newTestSession builds a session over real section-backed rings with a
// synthetic owner and no adapter. open is the recovery ring opener. Cleanup
// closes the session even after t.Fatal; tests that check Close's result call
// it themselves first, and a repeated Close returns the same result.
func newTestSession(t *testing.T, owner ringOwner, open func() (*rings, error)) *Session {
	t.Helper()
	r, err := allocateRings(MinCapacity)
	must(t, err)
	if err := r.createEvents(); err != nil {
		t.Fatal(errors.Join(err, r.close()))
	}
	r.owner = owner
	wake, err := windows.CreateEvent(nil, 1, 0, nil)
	must(t, err)
	cancel, err := windows.CreateEvent(nil, 1, 0, nil)
	must(t, err)
	s := &Session{adapter: &Adapter{config: Config{Name: "closeerr-test"}}, rings: r, wake: wake, cancelEvent: cancel,
		wakeOwner: winhandle.Open(wake, "test wake"), cancelOwner: winhandle.Open(cancel, "test cancel"),
		changed: make(chan struct{}), stop: make(chan struct{}), stopped: make(chan struct{}),
		repair: make(chan error, 1), events: make(chan Event, 8), open: open}
	go s.maintain()
	t.Cleanup(func() { s.Close() })
	return s
}

// newFaultySession builds a session whose ring owner reports a teardown error
// (and optionally that it had already exited). The returned counter records any
// call to the ring opener, which a lost session must never make.
func newFaultySession(t *testing.T, lost bool) (*Session, *atomic.Int64) {
	t.Helper()
	opened := &atomic.Int64{}
	s := newTestSession(t, &faultyOwner{lost: lost}, func() (*rings, error) {
		opened.Add(1)
		return nil, errors.New("ring opener must not be called for a lost session")
	})
	return s, opened
}

func waitForEvent(t *testing.T, s *Session, kind string) Event {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case e := <-s.Events():
			if e.Kind == kind {
				return e
			}
		case <-deadline:
			t.Fatalf("event %q never arrived", kind)
		}
	}
}

// A retirement error raised while handling a lost session must survive to
// Session.Close, even though the rings are gone before the stop handler runs.
// The expected removal/owner-exit cause is the terminal read error, not a
// cleanup failure, so Close reports only the real teardown error.
func TestSessionCloseReportsRetirementError(t *testing.T) {
	for _, lost := range []bool{false, true} {
		name := "adapter-removed"
		terminal := ErrAdapterRemoved
		if lost {
			name = "owner-exited"
			terminal = ErrRegistrarExited
		}
		t.Run(name, func(t *testing.T) {
			s, _ := newFaultySession(t, lost)
			s.fail(errOwnerLost)
			removed := waitForEvent(t, s, "removed")
			if !errors.Is(removed.Err, terminal) {
				t.Fatalf("terminal read error %v lacks %v", removed.Err, terminal)
			}
			if errors.Is(s.closeErr, errOwnerLost) || errors.Is(s.closeErr, ErrAdapterRemoved) {
				t.Fatalf("the session-loss cause leaked into the cleanup error: %v", s.closeErr)
			}
			// Before Close, a reader still sees the terminal reason, not the cleanup error.
			if n, readErr := s.ReadPacket(context.Background(), make([]byte, 64)); n != 0 || !errors.Is(readErr, terminal) || errors.Is(readErr, errTestRetire) {
				t.Fatalf("terminal read error is wrong: %d %v", n, readErr)
			}
			err := s.Close()
			if !errors.Is(err, errTestRetire) {
				t.Fatalf("Session.Close dropped the retirement error: %v", err)
			}
		})
	}
}

// A confirmed owner loss discovered during retirement must take precedence over
// a corruption cause that queued the recovery: the session is lost (adapter-
// removed plus owner-exit), the opener is never called (no in-place rebuild),
// and the retirement error is still preserved for Close.
func TestSessionCorruptionYieldsToConfirmedOwnerLoss(t *testing.T) {
	s, opened := newFaultySession(t, true) // retirement reveals the owner already exited
	// Corruption queues the recovery first; only during retirement does end()
	// report that the registrar had already exited.
	s.fail(fmt.Errorf("injected ring corruption: %w", ErrCorrupt))
	removed := waitForEvent(t, s, "removed")
	if opened.Load() != 0 {
		t.Fatalf("a confirmed owner loss rebuilt in place: opener called %d times", opened.Load())
	}
	if !errors.Is(removed.Err, ErrAdapterRemoved) || !errors.Is(removed.Err, ErrRegistrarExited) {
		t.Fatalf("terminal reason %v is not adapter-lost with the owner-exit identity", removed.Err)
	}
	if errors.Is(removed.Err, errTestRetire) {
		t.Fatalf("the retirement cleanup error leaked into the terminal reason: %v", removed.Err)
	}
	if err := s.Close(); !errors.Is(err, errTestRetire) {
		t.Fatalf("Session.Close dropped the retirement error after corruption yielded to loss: %v", err)
	}
}

// The clean-retirement variant. faultyOwner's retirement always fails, and a
// failed retirement never reopens, so the test above cannot show that the loss
// itself prevents the rebuild. Here retirement succeeds and only the completed-
// exit classification differs. The control, an owner still running at our stop,
// must reopen, which proves the opener count can observe a rebuild.
func TestSessionCorruptionYieldsToConfirmedOwnerLossCleanRetire(t *testing.T) {
	for _, lost := range []bool{true, false} {
		name := "owner-exited-first"
		if !lost {
			name = "control-owner-alive-reopens"
		}
		t.Run(name, func(t *testing.T) {
			// The markers appear only during retirement, as every registrar exit
			// makes the driver publish them, so the pre-stop sample finds none.
			s, opened := newLossSession(t, &lossOwner{lost: lost, publish: true})
			s.fail(fmt.Errorf("injected ring corruption: %w", ErrCorrupt))
			e := waitOutcome(t, s)
			if lost {
				if e.Kind != "removed" || opened.Load() != 0 {
					t.Fatalf("a confirmed owner loss gave %q (%v) and called the opener %d times", e.Kind, e.Err, opened.Load())
				}
				assertLoss(t, "terminal reason", e.Err, true)
			} else if e.Kind != "recovered" || opened.Load() != 1 {
				t.Fatalf("control: corruption with a live owner gave %q (%v), opener called %d times", e.Kind, e.Err, opened.Load())
			}
			must(t, s.Close())
			if stats := s.Stats(); stats.RecoveryFailures != 0 || stats.Recoveries != uint64(opened.Load()) {
				t.Fatalf("wrong recovery accounting with %d opener calls: %+v", opened.Load(), stats)
			}
		})
	}
}
