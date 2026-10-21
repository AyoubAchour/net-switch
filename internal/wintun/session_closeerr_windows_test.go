//go:build windows

package wintun

import (
	"context"
	"errors"
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

func newFaultySession(t *testing.T, lost bool) *Session {
	t.Helper()
	r, err := allocateRings(MinCapacity)
	must(t, err)
	if err := r.createEvents(); err != nil {
		t.Fatal(errors.Join(err, r.close()))
	}
	r.owner = &faultyOwner{lost: lost}
	wake, err := windows.CreateEvent(nil, 1, 0, nil)
	must(t, err)
	cancel, err := windows.CreateEvent(nil, 1, 0, nil)
	must(t, err)
	s := &Session{adapter: &Adapter{config: Config{Name: "closeerr-test"}}, rings: r, wake: wake, cancelEvent: cancel,
		wakeOwner: winhandle.Open(wake, "test wake"), cancelOwner: winhandle.Open(cancel, "test cancel"),
		changed: make(chan struct{}), stop: make(chan struct{}), stopped: make(chan struct{}),
		repair: make(chan error, 1), events: make(chan Event, 8)}
	go s.maintain()
	return s
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
			s := newFaultySession(t, lost)
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
