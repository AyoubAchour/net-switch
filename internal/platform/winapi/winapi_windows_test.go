//go:build windows

package winapi

import (
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

// A smoke test of the wrapper's behaviour on a stack-allocated handle
// literal: it waits on the right handle, times out and rejects an empty list.
// It cannot catch a regression to the unsafe x/sys shape, because a stack move
// between conversion and syscall is not something a test can force. That
// property is structural (the conversion sits inside the SyscallN argument
// list, after the procedure lookup) and is checked by review and escape
// analysis.
func TestWaitForMultipleObjectsWaitsOnTheRightHandle(t *testing.T) {
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
