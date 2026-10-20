package stack_test

import (
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// The pinned Go runtime reads coarse interrupt time on Windows ARM64. QPC
// measures short intervals without changing the machine's timer resolution.
// https://learn.microsoft.com/windows/win32/sysinfo/acquiring-high-resolution-time-stamps
func newLatencyClock(t testing.TB) func() time.Duration {
	dll := syscall.NewLazyDLL("kernel32.dll")
	counter := dll.NewProc("QueryPerformanceCounter")
	frequency := dll.NewProc("QueryPerformanceFrequency")
	read := func(proc *syscall.LazyProc) int64 {
		var value int64
		if ok, _, err := proc.Call(uintptr(unsafe.Pointer(&value))); ok == 0 {
			t.Fatalf("performance clock: %v", err)
		}
		return value
	}
	freq := read(frequency)
	if freq <= 0 {
		t.Fatal("invalid performance clock frequency", freq)
	}
	origin := read(counter)
	nanosPerTick := float64(time.Second) / float64(freq)
	return func() time.Duration {
		// Convert a short relative interval, not an uptime-sized counter.
		return time.Duration(float64(read(counter)-origin) * nanosPerTick)
	}
}
