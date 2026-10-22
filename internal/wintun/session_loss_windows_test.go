//go:build windows

package wintun

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// lossOwner is a synthetic registration owner whose retirement always
// succeeds, like a registrar that exits on its stop request. exit stands for
// its process handle (0 for none); lost is the completed-exit classification
// end reports; publish writes the driver's markers during retirement, as
// every registrar exit makes the driver do.
type lossOwner struct {
	exit          windows.Handle
	lost, publish bool
}

func (o *lossOwner) exited() windows.Handle { return o.exit }
func (o *lossOwner) end(r *rings, _ func(windows.Handle) error) (bool, error) {
	if o.publish {
		publishRelease(r, true)
	}
	r.ownerExitedFirst = o.lost
	return false, nil
}

// newLossSession starts a session with owner. Its opener counts calls and
// returns fresh synthetic rings, so a recovery that reopens is observable.
func newLossSession(t *testing.T, owner ringOwner) (*Session, *atomic.Int64) {
	t.Helper()
	opened := &atomic.Int64{}
	s := newTestSession(t, owner, func() (*rings, error) {
		opened.Add(1)
		r, err := allocateRings(MinCapacity)
		if err != nil {
			return nil, err
		}
		if err := r.createEvents(); err != nil {
			return nil, errors.Join(err, r.close())
		}
		r.owner = &lossOwner{}
		return r, nil
	})
	return s, opened
}

// publishRelease writes the driver's markers in its order: Receive.Head as its
// receive thread ends, then Send.Tail from unregistration.
func publishRelease(r *rings, sendTail bool) {
	r.receive.store(0, ^uint32(0))
	if sendTail {
		r.send.store(4, ^uint32(0))
	}
}

// queuePacket publishes p in the Send ring as the driver does: the size and
// bytes first, then Send.Tail.
func queuePacket(r *rings, p []byte) {
	tail := r.send.load(4)
	binary.LittleEndian.PutUint32(r.send.data()[tail:], uint32(len(p)))
	copy(r.send.data()[tail+4:], p)
	r.send.store(4, (tail+aligned(uint32(len(p))+4))&(r.send.capacity-1))
}

// waitOutcome returns the event that ends a repair: recovered, removed or
// failed. "recovering" only announces a reopen attempt.
func waitOutcome(t *testing.T, s *Session) Event {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case e, ok := <-s.Events():
			if !ok {
				t.Fatal("session stopped before the repair finished")
			}
			if e.Kind != "recovering" {
				return e
			}
		case <-deadline:
			t.Fatal("repair never finished")
		}
	}
}

// assertLoss checks the adapter-loss contract: ErrAdapterRemoved always, plus
// ErrRegistrarExited exactly for the owner's own exit.
func assertLoss(t *testing.T, what string, err error, ownerExit bool) {
	t.Helper()
	if !errors.Is(err, ErrAdapterRemoved) || errors.Is(err, ErrRegistrarExited) != ownerExit {
		t.Fatalf("%s: %v; want ErrAdapterRemoved with owner-exit identity %v", what, err, ownerExit)
	}
}

func lossRead(s *Session) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.ReadBatch(ctx, [][]byte{make([]byte, MaxPacketSize)}, make([]int, 1))
}

// lossWriteError returns the first WriteBatch error. A write that meets
// maintenance holding the session lock drops its batch and returns (0, nil).
func lossWriteError(t *testing.T, s *Session) error {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		n, err := s.WriteBatch([][]byte{testPacket()})
		if n != 0 {
			t.Fatalf("a lost session accepted %d packets", n)
		}
		if err != nil {
			return err
		}
		if time.Now().After(deadline) {
			t.Fatal("WriteBatch never reported the loss")
		}
		time.Sleep(time.Millisecond)
	}
}

// Driver markers already present when maintenance retires the owner mean the
// driver ended the registration itself, so a queued corruption must not
// rebuild, although the owner (still running) then exits cleanly on our stop.
// That is removal: ErrAdapterRemoved without the owner-exit identity. A lone
// Receive.Head is the window between the driver's two markers. In the control
// the markers appear only during retirement, as every registrar exit makes the
// driver publish them; that corruption must reopen.
func TestSessionCorruptionYieldsToPreStopDriverRelease(t *testing.T) {
	for _, tc := range []struct {
		name   string
		before int // markers published before the repair: none, Receive.Head, or both
	}{{"both-markers", 2}, {"receive-head-only", 1}, {"control-markers-at-stop-reopens", 0}} {
		t.Run(tc.name, func(t *testing.T) {
			s, opened := newLossSession(t, &lossOwner{publish: true})
			if tc.before != 0 {
				publishRelease(s.rings, tc.before == 2)
			}
			s.fail(fmt.Errorf("injected ring corruption: %w", ErrCorrupt))
			e := waitOutcome(t, s)
			if tc.before == 0 {
				if e.Kind != "recovered" || opened.Load() != 1 {
					t.Fatalf("control: corruption with markers only at stop gave %q (%v), opener called %d times", e.Kind, e.Err, opened.Load())
				}
				must(t, s.Close())
				return
			}
			if e.Kind != "removed" || opened.Load() != 0 {
				t.Fatalf("a pre-stop driver release gave %q (%v) and called the opener %d times", e.Kind, e.Err, opened.Load())
			}
			assertLoss(t, "terminal reason", e.Err, false)
			n, err := lossRead(s)
			if n != 0 {
				t.Fatalf("a removed session read %d packets", n)
			}
			assertLoss(t, "ReadBatch", err, false)
			assertLoss(t, "WriteBatch", lossWriteError(t, s), false)
			must(t, s.Close())
			if stats := s.Stats(); stats.Recoveries != 0 || stats.RecoveryFailures != 0 || opened.Load() != 0 {
				t.Fatalf("removal counted as recovery or rebuilt: %+v, opener called %d times", stats, opened.Load())
			}
		})
	}
}

// ReadBatch and WriteBatch carry the adapter-loss contract without a rebuild:
// ErrAdapterRemoved with ErrRegistrarExited for a confirmed owner exit, and
// ErrAdapterRemoved alone for removal. The writer classifies its own first
// error by a zero-time check of the owner's exit handle, on that loss path
// only. A reader under traffic never parks, so it finds the loss through the
// markers rather than the exit handle; a parked reader wakes on either. Once
// maintenance has retired the owner, both directions return its completed-
// exit classification.
func TestSessionLossSentinels(t *testing.T) {
	for _, tc := range []struct {
		name      string
		detector  string // "writer", "reader-traffic" or "reader-parked"
		markers   bool   // the driver published its markers before detection
		signalled bool   // the owner's exit handle is signalled before detection
		ownerExit bool   // retirement classifies the loss as the owner's own exit
	}{
		{"writer-owner-exited", "writer", true, true, true},
		// The driver publishes its markers from the owner's exit callback before
		// the process is signalled, so a writer in that window reports removal.
		{"writer-owner-exiting", "writer", true, false, true},
		{"writer-removed", "writer", true, false, false},
		{"reader-traffic-owner-exited", "reader-traffic", true, true, true},
		{"reader-traffic-removed", "reader-traffic", true, false, false},
		{"reader-parked-owner-exited", "reader-parked", false, true, true},
		{"reader-parked-removed", "reader-parked", true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exit, err := windows.CreateEvent(nil, 1, 0, nil) // a process handle stays signalled
			must(t, err)
			t.Cleanup(func() { windows.CloseHandle(exit) })
			s, opened := newLossSession(t, &lossOwner{exit: exit, lost: tc.ownerExit, publish: true})
			// Taken before any reader starts, so maintenance's later replacement
			// of s.rings is ordered after this read.
			r := s.rings
			trigger := func() {
				if tc.markers {
					publishRelease(r, true)
				}
				if tc.signalled {
					must(t, windows.SetEvent(exit))
				}
			}
			switch tc.detector {
			case "writer":
				trigger()
				n, err := s.WriteBatch([][]byte{testPacket()})
				if n != 0 {
					t.Fatalf("a released ring accepted %d packets", n)
				}
				// Only an exit handle already signalled confirms the owner's exit here.
				assertLoss(t, "first WriteBatch", err, tc.signalled)
			case "reader-traffic":
				queuePacket(r, testPacket())
				waits := s.Stats().ReadWaits
				if n, err := lossRead(s); n != 1 || err != nil {
					t.Fatalf("traffic read: %d %v", n, err)
				}
				trigger()
				n, err := lossRead(s)
				if n != 0 {
					t.Fatalf("a released ring read %d packets", n)
				}
				if s.Stats().ReadWaits != waits {
					t.Fatal("the reader parked; traffic was meant to keep it out of the exit wait")
				}
				assertLoss(t, "first ReadBatch", err, tc.ownerExit)
			case "reader-parked":
				readEvent := r.readHandle()
				waits := s.Stats().ReadWaits
				done := make(chan error, 1)
				go func() {
					_, err := lossRead(s)
					done <- err
				}()
				for deadline := time.Now().Add(5 * time.Second); s.Stats().ReadWaits == waits; {
					if time.Now().After(deadline) {
						t.Fatal("the reader never parked")
					}
					time.Sleep(time.Millisecond)
				}
				trigger()
				if tc.markers {
					must(t, windows.SetEvent(readEvent)) // the driver sets Send.TailMoved after Send.Tail
				}
				select {
				case err := <-done:
					assertLoss(t, "first ReadBatch", err, tc.ownerExit)
				case <-time.After(10 * time.Second):
					t.Fatal("the loss left the reader parked")
				}
			}
			if e := waitOutcome(t, s); e.Kind != "removed" {
				t.Fatalf("the loss gave %q (%v)", e.Kind, e.Err)
			}
			n, err := lossRead(s)
			if n != 0 {
				t.Fatalf("a lost session read %d packets", n)
			}
			assertLoss(t, "ReadBatch after retirement", err, tc.ownerExit)
			assertLoss(t, "WriteBatch after retirement", lossWriteError(t, s), tc.ownerExit)
			if opened.Load() != 0 {
				t.Fatalf("a lost session called the ring opener %d times", opened.Load())
			}
			must(t, s.Close())
			if stats := s.Stats(); stats.Recoveries != 0 || stats.RecoveryFailures != 0 {
				t.Fatalf("the loss counted as recovery: %+v", stats)
			}
		})
	}
}
