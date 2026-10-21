//go:build windows

package winengine

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"testing"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

// TEST ONLY, undocumented NT ABI, not a supported socket implementation API.
// Layout references inspected 2026-10-21:
// https://raw.githubusercontent.com/winsiderss/phnt/master/ntpsapi.h
// https://raw.githubusercontent.com/reactos/reactos/master/sdk/include/ndk/pstypes.h
// These agree on HANDLE, CLIENT_ID (two pointer-sized IDs), ULONG Type,
// PVOID Stacks[16]; QUERY has HANDLE, ULONG TotalTraces, aligned entries.
// ENABLE_EX is two ULONGs. This is an independently written ABI binding.
// Microsoft documents the OS facility, but not this binding, at:
// https://learn.microsoft.com/windows-hardware/drivers/debuggercmds/-htrace
// No driver, global flags, mitigation-policy or registry changes. The hosted
// controller uses CDB to handle tracing's first-chance bad-reference exception.
const socketTraceSlots = 16384

type socketTraceEntry struct {
	Handle windows.Handle
	PID    uintptr
	TID    uintptr
	Type   uint32
	Stack  [16]uintptr
}

type socketTraceQuery struct {
	Handle windows.Handle
	Total  uint32
	Entry  [socketTraceSlots]socketTraceEntry
}

var socketTraceSetup struct {
	sync.Once
	err error
}

func socketDiagnosticsEnabled() bool {
	return os.Getenv("NETSWITCH_SOCKET_DIAGNOSTICS") == "1"
}

// Call BEFORE creating the fixture's first socket. The focused invocation in
// SOCKET-DIAGNOSTICS.md excludes other tests which may create sockets earlier.
func startSocketDiagnostics(t *testing.T) bool {
	t.Helper()
	if !socketDiagnosticsEnabled() {
		return false
	}
	hosted(t)
	if !winhandle.Enabled {
		t.Fatal("socket diagnostics require the existing netswitch_handlecheck tripwire")
	}
	socketTraceSetup.Do(func() {
		socketTraceSetup.err = enableSocketTrace(t)
	})
	if socketTraceSetup.err != nil {
		t.Fatalf("socket diagnostics unavailable; no socket scenario ran: %v", socketTraceSetup.err)
	}
	return true
}

func enableSocketTrace(t *testing.T) error {
	// Both supported runner architectures have the same ABI. Refuse an
	// unverified layout rather than interpreting plausible-looking garbage.
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return fmt.Errorf("unverified trace architecture %s", runtime.GOARCH)
	}
	if unsafe.Sizeof(socketTraceEntry{}) != 160 ||
		unsafe.Offsetof(socketTraceEntry{}.PID) != 8 ||
		unsafe.Offsetof(socketTraceEntry{}.TID) != 16 ||
		unsafe.Offsetof(socketTraceEntry{}.Type) != 24 ||
		unsafe.Offsetof(socketTraceEntry{}.Stack) != 32 ||
		unsafe.Offsetof(socketTraceQuery{}.Total) != 8 ||
		unsafe.Offsetof(socketTraceQuery{}.Entry) != 16 {
		return errors.New("ProcessHandleTracing layout differs from reference headers")
	}
	// Validate the sentinel without tracing first. Once CDB handles a native
	// bad-reference exception, its continuation can change the observed return
	// value (zero on the ARM64 runner); that value is no longer an API oracle.
	invalid := windows.Handle(0x7ffffffc)
	queryInvalid := func() uint32 {
		var info [16]uint64
		var length uint32
		status, _, _ := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryObject").Call(
			uintptr(invalid), 0, uintptr(unsafe.Pointer(&info[0])), unsafe.Sizeof(info), uintptr(unsafe.Pointer(&length)))
		return uint32(status)
	}
	if status := queryInvalid(); status != 0xc0000008 {
		return fmt.Errorf("untraced invalid-reference control returned NTSTATUS=%#x", status)
	}
	config := struct{ Flags, Slots uint32 }{Slots: socketTraceSlots}
	if err := windows.NtSetInformationProcess(windows.CurrentProcess(), windows.ProcessHandleTracing,
		unsafe.Pointer(&config), uint32(unsafe.Sizeof(config))); err != nil {
		return fmt.Errorf("enable ProcessHandleTracing: %w", err)
	}
	// Prove actual OS OPEN and CLOSE records, not the winhandle registry's
	// account of them. Close exactly once; never operate on this value again.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tid := uintptr(windows.GetCurrentThreadId())
	h, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return err
	}
	if err := windows.CloseHandle(h); err != nil {
		return err
	}
	entries, err := querySocketTrace(h)
	if err != nil {
		return err
	}
	if !traceHas(entries, h, tid, 1) || !traceHas(entries, h, tid, 2) {
		return fmt.Errorf("OS trace positive control lacks OPEN/CLOSE: handle=%#x entries=%+v", h, entries)
	}
	logSocketTrace(t, "control/event", entries)
	// A READ-ONLY invalid reference, not a second close of a released value.
	// The actual BADREF record is mandatory, including its PID/TID and stack.
	// NtQueryObject cannot close or mutate a coincidentally valid sentinel.
	status := queryInvalid()
	if status != 0xc0000008 && status != 0 {
		return fmt.Errorf("traced invalid-reference control returned NTSTATUS=%#x", status)
	}
	entries, err = querySocketTrace(invalid)
	if err != nil {
		return err
	}
	if !traceHas(entries, invalid, tid, 3) {
		return fmt.Errorf("OS trace control lacks BADREF: entries=%+v", entries)
	}
	logSocketTrace(t, "control/invalid-reference", entries)
	t.Logf("SOCKET BADREF CALIBRATION untraced-status=0xc0000008 traced-status=%#x old-status-verdict=%t; traced proof requires the native BADREF record and debugger exception", status, status == 0xc0000008)
	all, err := querySocketTrace(0)
	if err != nil || !traceHas(all, h, tid, 1) || !traceHas(all, h, tid, 2) || !traceHas(all, invalid, tid, 3) {
		return fmt.Errorf("all-handles trace control lost known records: total=%d error=%v", len(all), err)
	}
	goFrames := 0
	for _, entry := range all {
		if entry.Handle == h && entry.Type == 2 && entry.PID == uintptr(os.Getpid()) && entry.TID == tid {
			for _, pc := range entry.Stack {
				if pc != 0 && runtime.FuncForPC(pc-1) != nil {
					goFrames++
				}
			}
		}
	}
	if goFrames == 0 {
		return errors.New("known close trace contains no resolvable Go frame; cannot attribute Go closers")
	}
	t.Logf("SOCKET TRACE CONTROL PASS arch=%s go=%s entry=160 stack-offset=32 query-offset=16 slots=%d all-records=%d resolved-Go-frames=%d; OS OPEN/CLOSE/BADREF with matching PID/TID",
		runtime.GOARCH, runtime.Version(), socketTraceSlots, len(all), goFrames)
	return nil
}

func traceHas(entries []socketTraceEntry, h windows.Handle, tid uintptr, kind uint32) bool {
	for _, e := range entries {
		if e.Handle == h && e.Type == kind && e.PID == uintptr(os.Getpid()) && e.TID == tid && e.Stack != [16]uintptr{} {
			return true
		}
	}
	return false
}

// closeTraceOn is set by TestMain when NETSWITCH_HANDLE_CLOSE_TRACE=1: OS
// handle tracing for the whole package run, from before any test creates a
// handle. It is for the intermittent duplicate-socket defect, where a handle
// we just created turned out to name a different, brand-new socket: the
// history of that value shows who closed it. Hosted CI only. With tracing on,
// any use of an invalid handle raises STATUS_INVALID_HANDLE; without a
// debugger that ends the process with the faulting stack, which is evidence
// too.
var closeTraceOn bool

func enableCloseTrace() error {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		return errors.New("only on disposable hosted CI")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" || unsafe.Sizeof(socketTraceEntry{}) != 160 {
		return fmt.Errorf("unverified trace layout on %s", runtime.GOARCH)
	}
	config := struct{ Flags, Slots uint32 }{Slots: socketTraceSlots}
	if err := windows.NtSetInformationProcess(windows.CurrentProcess(), windows.ProcessHandleTracing,
		unsafe.Pointer(&config), uint32(unsafe.Sizeof(config))); err != nil {
		return fmt.Errorf("enable ProcessHandleTracing: %w", err)
	}
	// Positive control: a real OPEN and CLOSE of a known value are recorded.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tid := uintptr(windows.GetCurrentThreadId())
	h, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return err
	}
	if err := windows.CloseHandle(h); err != nil {
		return err
	}
	entries, err := querySocketTrace(h)
	if err != nil {
		return err
	}
	if !traceHas(entries, h, tid, 1) || !traceHas(entries, h, tid, 2) {
		return fmt.Errorf("trace control lacks OPEN/CLOSE: handle=%#x entries=%d", h, len(entries))
	}
	closeTraceOn = true
	return nil
}

// handleFailureEvidence logs, at a handle identity failure, the OS history of
// each value (when the close trace is on) and every goroutine's stack, which
// shows background work left by earlier tests.
func handleFailureEvidence(t *testing.T, values map[string]windows.Handle) {
	t.Helper()
	if closeTraceOn {
		for role, h := range values {
			entries, err := querySocketTrace(h)
			if err != nil {
				t.Logf("HTRACE %s handle=%#x query: %v", role, h, err)
				continue
			}
			logSocketTrace(t, role, entries)
		}
	} else {
		t.Log("HTRACE off; set NETSWITCH_HANDLE_CLOSE_TRACE=1 on hosted CI to record every OPEN and CLOSE")
	}
	stacks := make([]byte, 1<<20)
	t.Logf("GOROUTINES AT FAILURE\n%s", stacks[:runtime.Stack(stacks, true)])
}

func querySocketTrace(h windows.Handle) ([]socketTraceEntry, error) {
	q := new(socketTraceQuery) // typed storage supplies native pointer alignment
	q.Handle = h
	var returned uint32
	err := windows.NtQueryInformationProcess(windows.CurrentProcess(), windows.ProcessHandleTracing,
		unsafe.Pointer(q), uint32(unsafe.Sizeof(*q)), &returned)
	if err != nil {
		return nil, fmt.Errorf("query htrace handle=%#x returned=%d total=%d: %w", h, returned, q.Total, err)
	}
	if q.Total > socketTraceSlots {
		return nil, fmt.Errorf("htrace overflow: total=%d capacity=%d", q.Total, socketTraceSlots)
	}
	need := unsafe.Offsetof(q.Entry) + uintptr(q.Total)*unsafe.Sizeof(socketTraceEntry{})
	if returned != 0 && uintptr(returned) < need {
		return nil, fmt.Errorf("short htrace output: returned=%d need=%d", returned, need)
	}
	entries := q.Entry[:q.Total:q.Total]
	for _, e := range entries {
		if e.Type < 1 || e.Type > 3 || (h != 0 && e.Handle != h) {
			return nil, fmt.Errorf("invalid htrace record: %+v", e)
		}
	}
	return entries, nil
}

// The API has no documented sequence number/order. Preserve its array index;
// do NOT present that index as time. Multiset subtraction handles identical
// stacks and repeated reuse without assuming either newest-first or reverse.
func socketTraceDelta(before, after []socketTraceEntry) []socketTraceEntry {
	counts := make(map[socketTraceEntry]int, len(before))
	for _, e := range before {
		counts[e]++
	}
	var delta []socketTraceEntry
	for _, e := range after {
		if counts[e] > 0 {
			counts[e]--
		} else {
			delta = append(delta, e)
		}
	}
	return delta
}

func logSocketTrace(t *testing.T, stage string, entries []socketTraceEntry) {
	t.Helper()
	t.Logf("HTRACE stage=%s records=%d (OS array order; finite history, not an ownership proof)", stage, len(entries))
	for i, e := range entries {
		// Bound a pathological reuse report, but make lost evidence explicit.
		if i == 512 {
			t.Logf("HTRACE TRUNCATED stage=%s omitted=%d; cannot rule out an unprinted close", stage, len(entries)-i)
			break
		}
		t.Logf("HTRACE stage=%s index=%d handle=%#x pid=%d tid=%d type=%s stack=%#x", stage, i,
			e.Handle, e.PID, e.TID, [...]string{"", "OPEN", "CLOSE", "BADREF"}[e.Type], e.Stack)
		for frame, pc := range e.Stack {
			if pc != 0 && e.PID == uintptr(os.Getpid()) {
				if fn := runtime.FuncForPC(pc - 1); fn != nil {
					file, line := fn.FileLine(pc - 1)
					t.Logf("HTRACE Go frame=%d pc=%#x function=%s source=%s:%d", frame, pc, fn.Name(), file, line)
				}
			}
		}
	}
}

func socketTraceModules(t *testing.T) {
	t.Helper()
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, uint32(os.Getpid()))
	if err != nil {
		t.Logf("HTRACE modules error=%v", err)
		return
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ModuleEntry32{Size: uint32(windows.SizeofModuleEntry32)}
	err = windows.Module32First(snapshot, &entry)
	for err == nil {
		t.Logf("HTRACE module=%s base=%#x size=%#x path=%s", windows.UTF16ToString(entry.Module[:]),
			entry.ModBaseAddr, entry.ModBaseSize, windows.UTF16ToString(entry.ExePath[:]))
		err = windows.Module32Next(snapshot, &entry)
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		t.Logf("HTRACE module enumeration error=%v", err)
	}
}

func TestSocketHandleTraceControl(t *testing.T) {
	if !startSocketDiagnostics(t) {
		t.Skip("opt in with NETSWITCH_SOCKET_DIAGNOSTICS=1 on hosted Windows")
	}
}
