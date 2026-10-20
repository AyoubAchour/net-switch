package lifecycle

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/buildinfo"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/internal/service"
)

type healthFunc func(context.Context) error

func (f healthFunc) Health(ctx context.Context) error { return f(ctx) }

type resumeCounter int

func (r *resumeCounter) Resume() { *r++ }

func TestEngineResumeOnlyControlsGrace(t *testing.T) {
	var calls resumeCounter
	for _, present := range []bool{false, true} {
		resumeEngine(&calls, "owner", func(string, uint32) (bool, error) { return present, nil }, func(string) {})
	}
	if calls != 1 {
		t.Fatal("engine must skip grace without an owner, not decide to stop routing", calls)
	}
	resumeEngine(&calls, "owner", func(string, uint32) (bool, error) { return false, errors.New("lookup failed") }, func(string) {})
	if calls != 2 {
		t.Fatal("unknown session state removed resume protection")
	}
}

func TestHealthWatchBoundsConsecutiveFailureAndResetsOnAnswers(t *testing.T) {
	now := time.Unix(100, 0)
	clock := func() time.Time { return now }
	var w healthWatch
	fail := healthFunc(func(ctx context.Context) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded probe")
		}
		now = now.Add(3 * time.Second)
		return context.DeadlineExceeded
	})
	for range 6 {
		if err := w.check(context.Background(), fail, clock); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.check(context.Background(), fail, clock); err == nil {
		t.Fatal("hung process not detected within 21 seconds")
	}
	answer := healthFunc(func(context.Context) error { now = now.Add(2 * time.Second); return nil })
	if err := w.check(context.Background(), answer, clock); err != nil {
		t.Fatal(err)
	}
	if w.failedFor != 0 {
		t.Fatal("slow successful response did not reset the failure window")
	}
	if err := w.check(context.Background(), fail, clock); err != nil {
		t.Fatal("old failures leaked into the new window")
	}
}

func TestHealthProbeAcrossStandbyCannotConsumeFailureWindow(t *testing.T) {
	now := time.Unix(100, 0)
	var watch healthWatch
	probe := healthFunc(func(context.Context) error { now = now.Add(8 * time.Hour); return context.DeadlineExceeded })
	if err := watch.check(context.Background(), probe, func() time.Time { return now }); err != nil {
		t.Fatal("standby was mistaken for a hung engine", err)
	}
}

func TestSessionQueryFailurePreservesRouting(t *testing.T) {
	stops := 0
	handleSessionEvent(service.Event{Logoff: true}, "owner", func(string, uint32) (bool, error) { return false, errors.New("WTS unavailable") }, func() error { stops++; return nil }, func(string) {})
	if stops != 0 {
		t.Fatal("lookup error was treated as a logoff")
	}
}

func TestAcknowledgedStopHasDeadlineAndForcesFailOpen(t *testing.T) {
	r, _ := fakeRemote(t, buildinfo.String())
	if err := r.Attach(r.ctx, false); err != nil {
		t.Fatal(err)
	}
	r.waitStopped = func(ctx context.Context, _ string) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("stop wait has no deadline")
		}
		<-ctx.Done()
		return ctx.Err()
	}
	killed := false
	r.forceStop = func(ctx context.Context, name string) error {
		if name != service.Engine {
			t.Fatal(name)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("forced stop is unbounded")
		}
		killed = true
		return nil
	}
	ctx, cancel := context.WithTimeout(r.ctx, 20*time.Millisecond)
	defer cancel()
	if err := r.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if !killed || r.Snapshot().Status != "off" {
		t.Fatal("stop did not force cleanup")
	}
}

func TestLeaseExitAfterRepeatedStandbyNeverBecomesCrash(t *testing.T) {
	for cycle := range 7 {
		r, _ := fakeRemote(t, buildinfo.String())
		if err := r.Attach(r.ctx, false); err != nil {
			t.Fatal(err)
		}
		r.mu.Lock()
		rpc := r.rpc
		r.mu.Unlock()
		r.dial = func(context.Context, localipc.Endpoint) (*localipc.Conn, error) {
			return nil, errors.New("lease expired during standby")
		}
		r.queryService = func(string) (service.Status, error) { return service.Status{Stopped: true}, nil }
		r.exitReason = func(instance string) (string, error) {
			if instance != "same-instance" {
				t.Fatal(instance)
			}
			return "lease-expired", nil
		}
		r.disconnect(rpc, errors.New("standby"))
		deadline := time.Now().Add(time.Second)
		for r.Snapshot().Status != "off" && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if s := r.Snapshot(); s.Status != "off" || s.FailureID != "" {
			t.Fatalf("cycle %d consumed crash budget: %+v", cycle, s)
		}
	}
}
