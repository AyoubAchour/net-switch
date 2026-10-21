//go:build windows

package wintun

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Every other registrar test runs the test binary itself as the helper. This
// one starts the built netswitch-engine.exe through the registrarExecutable
// seam and measures that process from the outside, so the footprint is the
// production image's, not the test binary's. The workflow builds the engine
// without test tags, records its SHA-256 and passes both in the environment.
const (
	productionEngineEnv       = "NETSWITCH_WINTUN_PRODUCTION_ENGINE"
	productionEngineSHA256Env = "NETSWITCH_WINTUN_PRODUCTION_ENGINE_SHA256"
	productionEngineModule    = "github.com/AyoubAchour/net-switch/cmd/netswitch-engine"
	memPrivate                = 0x20000   // MEMORY_BASIC_INFORMATION.Type for private memory
	memImage                  = 0x1000000 // MEMORY_BASIC_INFORMATION.Type for a mapped image
	objInherit                = 0x2       // HandleAttributes bit for an inheritable handle
)

var (
	isProcessInJob               = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")
	queryRegistrarJobInformation = windows.NewLazySystemDLL("kernel32.dll").NewProc("QueryInformationJobObject")
)

type engineProvenance struct {
	Path      string            `json:"path"`
	SHA256    string            `json:"sha256"`
	Module    string            `json:"module"`
	GoVersion string            `json:"goVersion"`
	Settings  map[string]string `json:"settings"`
}

type fileIdentity struct{ volume, high, low uint32 }

func identityOf(t *testing.T, path string) fileIdentity {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	must(t, err)
	h, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, 0, 0)
	must(t, err)
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	must(t, windows.GetFileInformationByHandle(h, &info))
	return fileIdentity{info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow}
}

func fileDigest(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	must(t, err)
	defer f.Close()
	h := sha256.New()
	_, err = io.Copy(h, f)
	must(t, err)
	return hex.EncodeToString(h.Sum(nil))
}

// productionEngine checks that the configured executable is the uninstrumented
// engine the workflow built and hashed, with the toolchain of this test binary.
func productionEngine(t *testing.T) engineProvenance {
	t.Helper()
	path := os.Getenv(productionEngineEnv)
	if path == "" {
		t.Skip("production registrar measurement needs " + productionEngineEnv)
	}
	requireRunner(t)
	if !filepath.IsAbs(path) || !strings.EqualFold(filepath.Base(path), "netswitch-engine.exe") {
		t.Fatalf("%s must be an absolute path to netswitch-engine.exe, got %q", productionEngineEnv, path)
	}
	want := strings.ToLower(strings.TrimSpace(os.Getenv(productionEngineSHA256Env)))
	if len(want) != 2*sha256.Size {
		t.Fatalf("%s must carry the SHA-256 recorded when the engine was built", productionEngineSHA256Env)
	}
	self, err := os.Executable()
	must(t, err)
	if identityOf(t, self) == identityOf(t, path) {
		t.Fatal("the production engine path names the test binary")
	}
	p := engineProvenance{Path: path, SHA256: fileDigest(t, path), Settings: map[string]string{}}
	if p.SHA256 != want {
		t.Fatalf("engine SHA-256 %s differs from the build step's %s", p.SHA256, want)
	}
	info, err := buildinfo.ReadFile(path)
	must(t, err)
	p.Module, p.GoVersion = info.Path, info.GoVersion
	for _, s := range info.Settings {
		p.Settings[s.Key] = s.Value
	}
	if p.Module != productionEngineModule {
		t.Fatalf("engine main package is %q, not %q", p.Module, productionEngineModule)
	}
	if strings.Contains(p.Settings["-tags"], "netswitch_handlecheck") || p.Settings["-race"] == "true" {
		t.Fatalf("engine is instrumented, not a release build: %v", p.Settings)
	}
	if p.GoVersion != runtime.Version() {
		t.Fatalf("engine built with %s, test binary with %s", p.GoVersion, runtime.Version())
	}
	return p
}

func processEntries(t *testing.T, match func(*windows.ProcessEntry32) bool) []windows.ProcessEntry32 {
	t.Helper()
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	must(t, err)
	defer windows.CloseHandle(snapshot)
	var found []windows.ProcessEntry32
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if match(&entry) {
			found = append(found, entry)
		}
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		t.Fatalf("process snapshot: %v", err)
	}
	return found
}

// engineChildren lists live processes started by this test process from the
// engine's image name, independently of anything the registrar reported.
func engineChildren(t *testing.T, image string) []windows.ProcessEntry32 {
	t.Helper()
	self, base := windows.GetCurrentProcessId(), filepath.Base(image)
	return processEntries(t, func(e *windows.ProcessEntry32) bool {
		return e.ParentProcessID == self && strings.EqualFold(windows.UTF16ToString(e.ExeFile[:]), base)
	})
}

func filetimeDuration(ft windows.Filetime) time.Duration {
	return time.Duration(uint64(ft.HighDateTime)<<32|uint64(ft.LowDateTime)) * 100
}

type helperFootprint struct {
	Handles           uint32  `json:"handles"`
	Threads           uint32  `json:"threads"`
	PrivateBytes      uint64  `json:"privateBytes"`
	WorkingSetBytes   uint64  `json:"workingSetBytes"`
	PeakWorkingSet    uint64  `json:"peakWorkingSetBytes"`
	PagefileBytes     uint64  `json:"pagefileBytes"`
	PeakPagefileBytes uint64  `json:"peakPagefileBytes"`
	CommittedPrivate  uint64  `json:"committedPrivateBytes"`
	CommittedMapped   uint64  `json:"committedMappedBytes"`
	CommittedImage    uint64  `json:"committedImageBytes"`
	RingViewBytes     uint64  `json:"ringViewCommittedBytes"`
	CPUMillis         float64 `json:"cpuMs"`
}

// sampleHelper reads the registrar's counters through a handle this test
// opened itself, and walks its address space for committed memory by type and
// for the ring view the registrar said it mapped.
func sampleHelper(t *testing.T, process windows.Handle, pid uint32, ringView uintptr) helperFootprint {
	t.Helper()
	var f helperFootprint
	if ok, _, err := getProcessHandleCount.Call(uintptr(process), uintptr(unsafe.Pointer(&f.Handles))); ok == 0 {
		t.Fatalf("registrar handle count: %v", err)
	}
	// PROCESS_MEMORY_COUNTERS_EX: PrivateUsage follows the ten base counters.
	type counters struct {
		Size, PageFaults                                                                                                          uint32
		PeakWorkingSet, WorkingSet, QuotaPeakPaged, QuotaPaged, QuotaPeakNonPaged, QuotaNonPaged, Pagefile, PeakPagefile, Private uintptr
	}
	m := counters{}
	m.Size = uint32(unsafe.Sizeof(m))
	if ok, _, err := getProcessMemoryInfo.Call(uintptr(process), uintptr(unsafe.Pointer(&m)), uintptr(m.Size)); ok == 0 {
		t.Fatalf("registrar memory counters: %v", err)
	}
	f.PrivateBytes, f.WorkingSetBytes, f.PeakWorkingSet = uint64(m.Private), uint64(m.WorkingSet), uint64(m.PeakWorkingSet)
	f.PagefileBytes, f.PeakPagefileBytes = uint64(m.Pagefile), uint64(m.PeakPagefile)
	entries := processEntries(t, func(e *windows.ProcessEntry32) bool { return e.ProcessID == pid })
	if len(entries) != 1 {
		t.Fatalf("registrar %d appears %d times in the process snapshot", pid, len(entries))
	}
	f.Threads = entries[0].Threads
	var created, exited, kernel, user windows.Filetime
	must(t, windows.GetProcessTimes(process, &created, &exited, &kernel, &user))
	f.CPUMillis = float64(filetimeDuration(kernel)+filetimeDuration(user)) / float64(time.Millisecond)
	for address, regions := uintptr(0), 0; ; regions++ {
		if regions > 1<<20 {
			t.Fatal("registrar address space walk did not end")
		}
		var region windows.MemoryBasicInformation
		if err := windows.VirtualQueryEx(process, address, &region, unsafe.Sizeof(region)); err != nil {
			if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
				break // past the highest user-mode address
			}
			t.Fatalf("registrar address space at %#x: %v", address, err)
		}
		if region.State == windows.MEM_COMMIT {
			switch region.Type {
			case memPrivate:
				f.CommittedPrivate += uint64(region.RegionSize)
			case memMapped:
				f.CommittedMapped += uint64(region.RegionSize)
				if region.AllocationBase == ringView {
					f.RingViewBytes += uint64(region.RegionSize)
				}
			case memImage:
				f.CommittedImage += uint64(region.RegionSize)
			}
		}
		next := region.BaseAddress + region.RegionSize
		if next <= address {
			break
		}
		address = next
	}
	return f
}

// helperHandleKinds counts the registrar's handles by kernel object type from
// the system handle table. Type indexes are named from this process's own
// entries in the same table through objectType; others stay numbered. It is
// reported, not gated: an own handle closed and reused between the table read
// and its type query could misname one index.
func helperHandleKinds(t *testing.T, pid uint32) (map[string]int, int) {
	t.Helper()
	size := uint32(8 << 20)
	var data []uint64 // pointer-aligned SYSTEM_HANDLE_INFORMATION_EX
	for {
		data = make([]uint64, size/8)
		var used uint32
		err := windows.NtQuerySystemInformation(windows.SystemExtendedHandleInformation, unsafe.Pointer(&data[0]), size, &used)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.STATUS_INFO_LENGTH_MISMATCH) || size >= 512<<20 {
			t.Fatalf("system handle table: %v", err)
		}
		size = max(2*size, (used+1<<20)&^7)
	}
	// Header: NumberOfHandles, Reserved. Each 40-byte entry: Object,
	// UniqueProcessId, HandleValue, GrantedAccess, CreatorBackTraceIndex,
	// ObjectTypeIndex, HandleAttributes, Reserved.
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&data[0])), len(data)*8)
	count := binary.LittleEndian.Uint64(raw[:8])
	if count > uint64((len(raw)-16)/40) {
		t.Fatal("invalid system handle table")
	}
	self := uint64(windows.GetCurrentProcessId())
	names := map[uint16]string{}
	var helperTypes []uint16
	inheritable := 0
	for i := uint64(0); i < count; i++ {
		e := raw[16+i*40 : 16+(i+1)*40]
		owner := binary.LittleEndian.Uint64(e[8:16])
		index := binary.LittleEndian.Uint16(e[30:32])
		switch owner {
		case uint64(pid):
			helperTypes = append(helperTypes, index)
			if binary.LittleEndian.Uint32(e[32:36])&objInherit != 0 {
				inheritable++
			}
		case self:
			if _, ok := names[index]; !ok {
				if kind, err := objectType(windows.Handle(binary.LittleEndian.Uint64(e[16:24]))); err == nil {
					names[index] = kind
				}
			}
		}
	}
	if len(helperTypes) == 0 {
		t.Fatalf("the system handle table lists no handles for registrar %d", pid)
	}
	kinds := map[string]int{}
	for _, index := range helperTypes {
		name, ok := names[index]
		if !ok {
			name = fmt.Sprintf("type#%d", index)
		}
		kinds[name]++
	}
	return kinds, inheritable
}

func sessionViewBytes(t *testing.T, s *Session) uint64 {
	t.Helper()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.rings == nil {
		t.Fatal("session has no rings")
	}
	return uint64(viewBytes(s.rings.send.capacity))
}

// TestWintunRegistrarProductionEngine starts a real production-size session
// whose registrar is the built release engine, then verifies independently of
// the registrar's own reply: the only engine child of this process is the
// session's registrar, its image is the hashed engine file, it sits in the
// session's kill-on-close job, it maps the ring view, and it was created by
// this session start. It records the footprint from outside and from the
// registrar's self-report, without a memory budget: the design states none.
// After Close the registrar must have exited cleanly, no engine child may
// remain and the adapter must be gone.
func TestWintunRegistrarProductionEngine(t *testing.T) {
	engine := productionEngine(t)
	self, err := os.Executable()
	must(t, err)
	if leftovers := engineChildren(t, engine.Path); len(leftovers) != 0 {
		t.Fatalf("%d engine processes already run under this test before the session", len(leftovers))
	}
	previous := registrarExecutable
	registrarExecutable = func() (string, error) { return engine.Path, nil }
	t.Cleanup(func() { registrarExecutable = previous })
	_, err = loadLibrary() // the DLL's guarded image file is not a session handle
	must(t, err)
	warmRuntimeThreads()
	debug.FreeOSMemory()
	guard := newDeviceFileGuard(t)
	a := newAdapter(t, 0)
	instance := a.InstanceID()
	called := time.Now()
	f := fixtureOnAdapter(t, "ours", a)
	ready := time.Now()
	s := f.io.(*Session)
	stats := s.Stats().Registrar

	children := engineChildren(t, engine.Path)
	pids := make([]uint32, len(children))
	for i, c := range children {
		pids[i] = c.ProcessID
	}
	if len(children) != 1 || children[0].ProcessID != stats.PID || stats.Starts != 1 {
		t.Fatalf("engine children %v, want only the session's registrar %+v", pids, stats)
	}
	g, launched := sessionRegistrar(t, s)
	defer windows.CloseHandle(launched)
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.SYNCHRONIZE, false, stats.PID)
	must(t, err)
	defer windows.CloseHandle(process)
	if !sameObject(process, launched) {
		t.Fatalf("PID %d does not name the process the session launched", stats.PID)
	}
	name := make([]uint16, 4096)
	size := uint32(len(name))
	must(t, windows.QueryFullProcessImageName(process, 0, &name[0], &size))
	image := windows.UTF16ToString(name[:size])
	if identityOf(t, image) != identityOf(t, engine.Path) {
		t.Fatalf("registrar image %q is not the hashed engine %q", image, engine.Path)
	}
	var created, exitedAt, kernel, user windows.Filetime
	must(t, windows.GetProcessTimes(process, &created, &exitedAt, &kernel, &user))
	createdAt := time.Unix(0, created.Nanoseconds())
	if createdAt.Before(called.Add(-500*time.Millisecond)) || createdAt.After(ready.Add(500*time.Millisecond)) {
		t.Fatalf("registrar created at %v, outside this session start [%v, %v]", createdAt, called, ready)
	}
	var inJob int32
	if ok, _, err := isProcessInJob.Call(uintptr(process), uintptr(g.job.Handle("test registrar job membership")), uintptr(unsafe.Pointer(&inJob))); ok == 0 {
		t.Fatalf("IsProcessInJob: %v", err)
	}
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	// As in the launcher, keep the conversion at the annotated Call boundary;
	// the uintptr-taking x/sys QueryInformationJobObject wrapper cannot pin it.
	if ok, _, err := queryRegistrarJobInformation.Call(uintptr(g.job.Handle("test registrar job limits")), windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits), 0); ok == 0 {
		t.Fatalf("QueryInformationJobObject: %v", err)
	}
	killOnClose := limits.BasicLimitInformation.LimitFlags&windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE != 0
	if inJob == 0 || !killOnClose || limits.BasicLimitInformation.ActiveProcessLimit != 1 {
		t.Fatalf("registrar job: member=%v kill-on-close=%v active limit=%d", inJob != 0, killOnClose, limits.BasicLimitInformation.ActiveProcessLimit)
	}
	guard.assertNone(t)

	ringView, wantView := uintptr(g.reply.Address), sessionViewBytes(t, s)
	afterStart := sampleHelper(t, process, stats.PID, ringView)
	kinds, inheritable := helperHandleKinds(t, stats.PID)
	exchange(t, 64)
	afterTraffic := sampleHelper(t, process, stats.PID, ringView)
	report(t, map[string]any{"test": "registrar_production_engine", "arch": runtime.GOARCH, "engine": engine,
		"test_binary": self, "test_binary_sha256": fileDigest(t, self), "registrar_pid": stats.PID, "registrar_image": image,
		"registrar_start_ms": float64(stats.StartNanos) / 1e6, "session_ready_ms": float64(ready.Sub(called)) / 1e6,
		"registrar_created_after_call_ms": float64(createdAt.Sub(called)) / 1e6,
		"self_reported": map[string]any{"measured": stats.FootprintMeasured, "handles": stats.Handles,
			"privateBytes": stats.PrivateBytes, "goHeapAllocBytes": stats.HeapBytes, "goStackInuseBytes": stats.StackBytes},
		"independent_after_start": afterStart, "independent_after_traffic": afterTraffic,
		"private_delta_over_traffic_bytes": int64(afterTraffic.PrivateBytes) - int64(afterStart.PrivateBytes),
		"handle_kinds":                     kinds, "inheritable_handles": inheritable, "ring_view_bytes": wantView, "exchanges": 64,
		"job_kill_on_close": killOnClose, "job_active_process_limit": limits.BasicLimitInformation.ActiveProcessLimit})
	if !stats.FootprintMeasured || stats.PrivateBytes == 0 || stats.Handles == 0 {
		t.Fatalf("registrar self-report is unmeasured: %+v", stats)
	}
	if afterStart.PrivateBytes == 0 || afterStart.Handles == 0 || afterStart.Threads == 0 {
		t.Fatalf("independent registrar counters are empty: %+v", afterStart)
	}
	if afterStart.RingViewBytes < wantView || afterTraffic.RingViewBytes < wantView {
		t.Fatalf("registrar maps %d/%d committed bytes at its reported view %#x, want %d", afterStart.RingViewBytes, afterTraffic.RingViewBytes, ringView, wantView)
	}

	f.stopEcho()
	if f.faults.Load() != 0 {
		t.Fatalf("production registrar session packet path failed: %v", f.fault())
	}
	closeStarted := time.Now()
	must(t, s.Close())
	closeTook := time.Since(closeStarted)
	gone, code := exitState(process, time.Second)
	if !gone || code != 0 {
		t.Fatalf("production registrar did not exit cleanly after Close: exited=%v code=%#x", gone, code)
	}
	if left := engineChildren(t, engine.Path); len(left) != 0 {
		t.Fatalf("%d engine processes outlived the session", len(left))
	}
	must(t, a.Close())
	assertPnPAbsent(t, instance)
	if digest := fileDigest(t, engine.Path); digest != engine.SHA256 {
		t.Fatalf("engine file changed during the run: %s, was %s", digest, engine.SHA256)
	}
	report(t, map[string]any{"test": "registrar_production_engine_cleanup", "arch": runtime.GOARCH, "registrar_pid": stats.PID,
		"registrar_exit_code": code, "session_close_ms": float64(closeTook) / 1e6, "engine_children_left": 0, "adapter_removed": true})
}
