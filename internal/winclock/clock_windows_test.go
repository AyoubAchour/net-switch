//go:build windows

package winclock

import (
	"context"
	"os"
	"slices"
	"testing"
	"time"
)

func TestNativeShortWaitsUseElapsedTime(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Skip("native timing evidence runs on hosted Windows")
	}
	for _, delay := range []time.Duration{time.Millisecond, 2 * time.Millisecond, 5 * time.Millisecond, 10 * time.Millisecond} {
		var samples []time.Duration
		for range 32 {
			start := Now()
			if err := System.Wait(context.Background(), delay); err != nil {
				t.Fatal(err)
			}
			elapsed := Since(start)
			if elapsed < delay {
				t.Fatalf("%v delay returned early after %v", delay, elapsed)
			}
			samples = append(samples, elapsed)
		}
		slices.Sort(samples)
		t.Logf("WINDOWS PRECISE WAIT requested_us=%d min_us=%d p95_us=%d max_us=%d",
			delay.Microseconds(), samples[0].Microseconds(), samples[30].Microseconds(), samples[31].Microseconds())
	}
}

type fakeWake struct {
	fn      func()
	stopped bool
	delay   time.Duration
}

func (w *fakeWake) Stop() bool {
	active := !w.stopped
	w.stopped = true
	return active
}

// The coarse scheduler can dispatch early at a 16 ms tick boundary, or deliver
// an already-queued callback after Stop. Neither may advance precise deadlines.
func TestCoarseWakeupsCannotFireEarlyOrReviveStoppedTimer(t *testing.T) {
	now := time.Duration(0)
	var wakes []*fakeWake
	source := Source{Now: func() time.Duration { return now }, Schedule: func(d time.Duration, f func()) Stopper {
		w := &fakeWake{fn: f, delay: d}
		wakes = append(wakes, w)
		return w
	}}
	fired := 0
	timer := source.AfterFunc(2*time.Millisecond, func() { fired++ })
	now = 50 * time.Microsecond
	wakes[0].fn()
	if fired != 0 || len(wakes) != 2 || wakes[1].delay != 1950*time.Microsecond {
		t.Fatalf("early coarse tick advanced the deadline: fired=%d wakes=%+v", fired, wakes)
	}
	now = 2 * time.Millisecond
	wakes[1].fn()
	if fired != 1 || timer.Stop() {
		t.Fatal("precise deadline did not expire once")
	}
	timer.Reset(2 * time.Millisecond)
	stale := wakes[2]
	if !timer.Stop() {
		t.Fatal("active timer was not stopped")
	}
	timer.Reset(5 * time.Millisecond)
	stale.fn()
	if fired != 1 || len(wakes) != 4 {
		t.Fatal("stale callback rearmed or fired a replacement timer")
	}
	now = 7 * time.Millisecond
	wakes[3].fn()
	if fired != 2 {
		t.Fatal("reset deadline did not expire")
	}
}

func TestCoarseClockCannotExtendLookupBudget(t *testing.T) {
	now := time.Duration(0)
	var wakes []*fakeWake
	source := Source{Now: func() time.Duration { return now }, Schedule: func(d time.Duration, f func()) Stopper {
		w := &fakeWake{fn: f, delay: d}
		wakes = append(wakes, w)
		return w
	}}
	ctx, cancel := source.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	now = 48 * time.Millisecond // coarse tick says 48 ms; precise deadline is later.
	wakes[0].fn()
	if ctx.Err() != nil || wakes[1].delay != 2*time.Millisecond {
		t.Fatal("coarse early wake expired the lookup")
	}
	now = 50 * time.Millisecond // the coarse clock could still be at 48 ms.
	wakes[1].fn()
	if ctx.Err() != context.DeadlineExceeded {
		t.Fatalf("precise deadline was lost: %v", ctx.Err())
	}
}
