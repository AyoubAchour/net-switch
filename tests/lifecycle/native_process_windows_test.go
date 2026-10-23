package lifecycle_test

import (
	"golang.org/x/sys/windows"
	"testing"
)

func pinNativeChild(t *testing.T, pid uint32) (func() bool, func() (uint32, bool), func()) {
	t.Helper()
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION|0x0800, false, pid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { windows.CloseHandle(h) })
	gone := func() bool {
		state, err := windows.WaitForSingleObject(h, 0)
		if err != nil {
			t.Fatal(err)
		}
		return state == windows.WAIT_OBJECT_0
	}
	if gone() {
		t.Fatal("native child was already dead before fault")
	}
	return gone, func() (uint32, bool) {
			var code uint32
			if !gone() {
				return 0, false
			}
			err := windows.GetExitCodeProcess(h, &code)
			return code, err == nil
		}, func() {
			status, _, _ := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtResumeProcess").Call(uintptr(h))
			if int32(status) < 0 && !gone() {
				t.Errorf("resume pinned native process: %#x", status)
			}
		}
}
