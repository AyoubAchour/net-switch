package lifecycle_test

import (
	"golang.org/x/sys/windows"
	"testing"
)

func suspendAdapter(t *testing.T, pid uint32) {
	t.Helper()
	h, err := windows.OpenProcess(0x0800, false, pid) // PROCESS_SUSPEND_RESUME
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	status, _, _ := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtSuspendProcess").Call(uintptr(h))
	if int32(status) < 0 {
		t.Fatalf("NtSuspendProcess: %#x", status)
	}
}
