package lifecycle_test

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsWorker struct {
	pid    uint32
	handle windows.Handle
}

func (w *windowsWorker) id() uint32 { return w.pid }
func (w *windowsWorker) close()     { windows.CloseHandle(w.handle) }
func (w *windowsWorker) alive() bool {
	var code uint32
	return windows.GetExitCodeProcess(w.handle, &code) == nil && code == 259
}
func (w *windowsWorker) suspend() error {
	result, _, _ := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtSuspendProcess").Call(uintptr(w.handle))
	if result != 0 {
		return fmt.Errorf("suspend worker: 0x%x", result)
	}
	return nil
}
func findWorkers(t *testing.T, parent uint32, directory string) []workerRef {
	t.Helper()
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	var refs []workerRef
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if entry.ParentProcessID != parent {
			continue
		}
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_SUSPEND_RESUME, false, entry.ProcessID)
		if err != nil {
			continue
		}
		var path [32768]uint16
		size := uint32(len(path))
		err = windows.QueryFullProcessImageName(h, 0, &path[0], &size)
		if err != nil || !strings.EqualFold(windows.UTF16ToString(path[:size]), filepath.Join(directory, "netswitch-engine.exe")) {
			windows.CloseHandle(h)
			continue
		}
		refs = append(refs, &windowsWorker{pid: entry.ProcessID, handle: h})
	}
	if err != windows.ERROR_NO_MORE_FILES {
		t.Fatal(err)
	}
	return refs
}
func assertServiceIsolation(t *testing.T, control, engine uint32) {
	t.Helper()
	for _, pid := range []uint32{control, engine} {
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			t.Fatal(err)
		}
		var inJob uint32
		ok, _, err := windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob").Call(uintptr(h), 0, uintptr(unsafe.Pointer(&inJob)))
		windows.CloseHandle(h)
		if ok == 0 {
			t.Fatal(err)
		}
		if inJob != 0 {
			t.Fatalf("service %d is in a worker job", pid)
		}
	}
}
