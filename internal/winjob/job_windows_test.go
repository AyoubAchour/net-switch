//go:build windows

package winjob

import (
	"testing"

	"golang.org/x/sys/windows"
)

// A job object with no process in it touches nothing outside this test.
func TestSetThenQueryRoundTrips(t *testing.T) {
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
	if err := Set(job, windows.JobObjectExtendedLimitInformation, &want); err != nil {
		t.Fatal(err)
	}
	var got windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if err := Query(job, windows.JobObjectExtendedLimitInformation, &got); err != nil {
		t.Fatal(err)
	}
	if got.BasicLimitInformation.LimitFlags != want.BasicLimitInformation.LimitFlags || got.BasicLimitInformation.ActiveProcessLimit != 1 || got.ProcessMemoryLimit != want.ProcessMemoryLimit {
		t.Fatalf("limits did not round-trip: %+v", got)
	}
	ui := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: windows.JOB_OBJECT_UILIMIT_DESKTOP}
	if err := Set(job, windows.JobObjectBasicUIRestrictions, &ui); err != nil {
		t.Fatal(err)
	}
	if err := Set[windows.JOBOBJECT_BASIC_UI_RESTRICTIONS](windows.InvalidHandle, windows.JobObjectBasicUIRestrictions, &ui); err == nil {
		t.Fatal("invalid handle accepted")
	}
}
