//go:build windows

package winapi

import (
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// A job object with no process in it touches nothing outside this test.
func TestJobInformationRoundTrips(t *testing.T) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(job)
	want := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags:         windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS | windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY,
			ActiveProcessLimit: 1,
		},
		ProcessMemoryLimit: 256 * 1024 * 1024,
	}
	if err := SetJobInformation(job, windows.JobObjectExtendedLimitInformation, &want); err != nil {
		t.Fatal(err)
	}
	var got windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if err := QueryJobInformation(job, windows.JobObjectExtendedLimitInformation, &got); err != nil {
		t.Fatal(err)
	}
	if got.BasicLimitInformation.LimitFlags != want.BasicLimitInformation.LimitFlags || got.BasicLimitInformation.ActiveProcessLimit != 1 || got.ProcessMemoryLimit != want.ProcessMemoryLimit {
		t.Fatalf("limits did not round-trip: %+v", got)
	}
	ui := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: windows.JOB_OBJECT_UILIMIT_DESKTOP}
	if err := SetJobInformation(job, windows.JobObjectBasicUIRestrictions, &ui); err != nil {
		t.Fatal(err)
	}
	if err := SetJobInformation(windows.InvalidHandle, windows.JobObjectBasicUIRestrictions, &ui); err == nil {
		t.Fatal("invalid handle accepted")
	}
}

// grow forces stack growth so a caller's stack-allocated array really moves.
//
//go:noinline
func grow(n int) byte {
	var pad [1024]byte
	if n == 0 {
		return pad[0]
	}
	return grow(n-1) + pad[n%len(pad)]
}

// The handle array is a small literal that escape analysis keeps on the
// stack. Its stack is grown between building it and waiting on it, and a
// second goroutine signals the second event while the wait runs, so the
// kernel must still be reading the real handles.
func TestWaitForMultipleObjectsReadsTheLiveArray(t *testing.T) {
	first, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(first)
	second, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(second)
	go func() {
		time.Sleep(20 * time.Millisecond)
		windows.SetEvent(second)
	}()
	for range 50 {
		handles := [2]windows.Handle{first, second}
		_ = grow(64)
		runtime.Gosched()
		got, err := WaitForMultipleObjects(handles[:], false, 5000)
		if err != nil {
			t.Fatal(err)
		}
		if got != windows.WAIT_OBJECT_0+1 {
			t.Fatalf("wait returned %#x, want the second handle", got)
		}
	}
	if got, err := WaitForMultipleObjects([]windows.Handle{first}, false, 0); err != nil || got != uint32(windows.WAIT_TIMEOUT) {
		t.Fatal("unsignalled handle did not time out", got, err)
	}
	if _, err := WaitForMultipleObjects(nil, false, 0); err == nil {
		t.Fatal("empty handle list accepted")
	}
}
