package lifecycle_test

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsWorker struct {
	pid    uint32
	handle windows.Handle
	mode   string
	t      *testing.T
}

func (w *windowsWorker) id() uint32   { return w.pid }
func (w *windowsWorker) kind() string { return w.mode }
func (w *windowsWorker) close()       { windows.CloseHandle(w.handle) }
func (w *windowsWorker) alive() bool {
	var code uint32
	if err := windows.GetExitCodeProcess(w.handle, &code); err != nil {
		w.t.Fatalf("read worker state %s/%d: %v", w.mode, w.pid, err)
	}
	return code == 259
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
		args, err := processArguments(h)
		if err != nil {
			windows.CloseHandle(h)
			t.Logf("worker command line %d unavailable: %v", entry.ProcessID, err)
			continue
		}
		if len(args) != 3 || args[1] != "worker" || (args[2] != "network" && args[2] != "meters" && args[2] != "outside") {
			windows.CloseHandle(h)
			continue
		}
		refs = append(refs, &windowsWorker{pid: entry.ProcessID, handle: h, mode: args[2], t: t})
	}
	if err != windows.ERROR_NO_MORE_FILES {
		t.Fatal(err)
	}
	return refs
}
func processArguments(handle windows.Handle) ([]string, error) {
	// NtQueryInformationProcess probes this as a pointer-aligned structure.
	// A byte array may be stack allocated at a one-byte-aligned address.
	command := make([]uint64, 8192)
	var needed uint32
	if err := windows.NtQueryInformationProcess(handle, windows.ProcessCommandLineInformation, unsafe.Pointer(&command[0]), uint32(len(command)*8), &needed); err != nil {
		return nil, err
	}
	text := (*windows.NTUnicodeString)(unsafe.Pointer(&command[0])).String()
	args, err := windows.DecomposeCommandLine(text)
	runtime.KeepAlive(command)
	return args, err
}
func TestProcessArgumentsUsesAlignedNativeBuffer(t *testing.T) {
	args, err := processArguments(windows.CurrentProcess())
	if err != nil || len(args) == 0 {
		t.Fatal("read-only process argument query", args, err)
	}
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
	// Only Control reads owner sessions (WTSQueryUserToken); the Engine's
	// required-privilege list leaves SeTcbPrivilege out of its token.
	if !servicePrivilege(t, control, "SeTcbPrivilege") || servicePrivilege(t, engine, "SeTcbPrivilege") {
		t.Fatal("SeTcbPrivilege must be in Control's token and absent from the Engine's")
	}
	t.Log("SeTcbPrivilege: present in Control, absent from Engine")
}

func servicePrivilege(t *testing.T, pid uint32, name string) bool {
	t.Helper()
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	var token windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); err != nil {
		t.Fatal("open service token", pid, err)
	}
	defer token.Close()
	var want windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &want); err != nil {
		t.Fatal(err)
	}
	var size uint32
	_ = windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &size)
	words := make([]uint64, (size+7)/8+1)
	if err := windows.GetTokenInformation(token, windows.TokenPrivileges, (*byte)(unsafe.Pointer(&words[0])), uint32(len(words)*8), &size); err != nil {
		t.Fatal(err)
	}
	privileges := (*windows.Tokenprivileges)(unsafe.Pointer(&words[0]))
	for _, p := range privileges.AllPrivileges() {
		if p.Luid == want {
			return true
		}
	}
	return false
}
