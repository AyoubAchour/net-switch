package lifecycle_test

import (
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func nativeImage(t *testing.T, pid uint32) string {
	t.Helper()
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	b := make([]uint16, 32768)
	size := uint32(len(b))
	if err := windows.QueryFullProcessImageName(h, 0, &b[0], &size); err != nil {
		t.Fatal(err)
	}
	return windows.UTF16ToString(b[:size])
}

func resumeNative(t *testing.T, pid uint32) {
	t.Helper()
	h, err := windows.OpenProcess(0x0800, false, pid)
	if err != nil {
		t.Error("resume native engine", err)
		return
	}
	defer windows.CloseHandle(h)
	status, _, _ := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtResumeProcess").Call(uintptr(h))
	if int32(status) < 0 {
		t.Errorf("NtResumeProcess: %#x", status)
	}
}

func assertNativeCapture(t *testing.T, _ string, fixture tunFixture) { fixture.installed(t) }

func waitNativeCleanup(t *testing.T, fixture tunFixture) {
	wait(t, "SCM native recovery command removes capture", 20*time.Second, func() bool {
		index, routes, err := nativeTUNState(0)
		return err == nil && index == 0 && routes == 0
	})
	fixture.clean(t)
}
