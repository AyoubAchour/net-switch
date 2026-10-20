//go:build windows

// Package winclock measures short intervals with Windows' performance counter.
// Go's Windows time.Now reads the coarser interrupt clock, even when its timers
// use high-resolution waitable timers. These are different clock guarantees.
package winclock

import (
	"context"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var kernel = windows.NewLazySystemDLL("kernel32.dll")
var counter = kernel.NewProc("QueryPerformanceCounter")
var frequency = sync.OnceValue(func() int64 {
	var hz int64
	ok, _, _ := kernel.NewProc("QueryPerformanceFrequency").Call(uintptr(unsafe.Pointer(&hz)))
	if ok == 0 || hz <= 0 {
		panic("Windows performance counter unavailable")
	}
	return hz
})

// Now returns a monotonic nanosecond count, not a wall-clock timestamp.
func Now() time.Duration {
	hz := frequency()
	var ticks int64
	counter.Call(uintptr(unsafe.Pointer(&ticks))) // Guaranteed on supported Windows.
	// Divide before multiplying so a machine's uptime cannot overflow ticks*1e9.
	return time.Duration(ticks/hz)*time.Second + time.Duration(float64(ticks%hz)*float64(time.Second)/float64(hz))
}

func Since(start time.Duration) time.Duration { return Now() - start }

// Source keeps timer wakeups separate from interval measurement. A coarse
// timer may wake early; only the precise clock decides that a deadline passed.
type Source struct {
	Now      func() time.Duration
	Schedule func(time.Duration, func()) Stopper
}

type Stopper interface{ Stop() bool }

var System = Source{Now: Now, Schedule: func(d time.Duration, f func()) Stopper { return time.AfterFunc(d, f) }}

type Timer struct {
	mu     sync.Mutex
	source Source
	wake   Stopper
	due    time.Duration
	serial uint64
	active bool
	fn     func()
}

func (s Source) AfterFunc(d time.Duration, f func()) *Timer {
	t := &Timer{source: s, fn: f}
	t.Reset(d)
	return t
}

func (t *Timer) Reset(d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.wake != nil {
		t.wake.Stop()
	}
	t.serial++
	t.active = true
	t.due = t.source.Now() + max(d, 0)
	t.arm(max(d, 0), t.serial)
}

// Called under mu. Every early wake is followed by a positive remaining delay;
// there is no spin loop even if a fake/coarse Go clock has not moved at all.
func (t *Timer) arm(d time.Duration, serial uint64) {
	t.wake = t.source.Schedule(d, func() {
		t.mu.Lock()
		if !t.active || t.serial != serial {
			t.mu.Unlock()
			return
		}
		if remaining := t.due - t.source.Now(); remaining > 0 {
			t.arm(max(remaining, 100*time.Microsecond), serial)
			t.mu.Unlock()
			return
		}
		t.active = false
		t.mu.Unlock()
		t.fn()
	})
}

func (t *Timer) Stop() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	active := t.active
	t.active = false
	t.serial++
	t.wake.Stop()
	return active
}

func (s Source) Wait(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.WaitDone(ctx.Done(), d)
	return ctx.Err()
}

// WaitDone also serves ring and completion services whose lifetime is a channel.
// A nil stop channel is allowed. False means cancellation, true means elapsed.
func (s Source) WaitDone(stop <-chan struct{}, d time.Duration) bool {
	done := make(chan struct{})
	t := s.AfterFunc(d, func() { close(done) })
	defer t.Stop()
	select {
	case <-stop:
		return false
	case <-done:
		return true
	}
}

type deadlineContext struct {
	context.Context
	deadline time.Time
}

func (c deadlineContext) Deadline() (time.Time, bool) { return c.deadline, true }
func (c deadlineContext) Err() error {
	if c.Context.Err() == nil {
		return nil
	}
	if context.Cause(c.Context) == context.DeadlineExceeded {
		return context.DeadlineExceeded
	}
	return context.Canceled
}

// WithTimeout preserves parent cancellation and uses the precise clock for its
// own timeout. Deadline is informational; the coarse clock does not fire it.
func (s Source) WithTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancelCause(parent)
	deadline := time.Now().Add(d)
	if prior, ok := parent.Deadline(); ok && prior.Before(deadline) {
		deadline = prior
	}
	t := s.AfterFunc(d, func() { cancel(context.DeadlineExceeded) })
	stop := context.AfterFunc(ctx, func() { t.Stop() })
	return deadlineContext{ctx, deadline}, func() { stop(); t.Stop(); cancel(context.Canceled) }
}
