//go:build windows

package wintun

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ---- refusal and fault fixtures (no adapter required) ----

func runRegistrarChild(t *testing.T, config *registrarConfig, inherit []syscall.Handle) (int, string) {
	t.Helper()
	exe, err := os.Executable()
	must(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, RegistrarMode)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, AdditionalInheritedHandles: inherit}
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if config != nil {
		encoded, err := json.Marshal(config)
		must(t, err)
		cmd.Stdin = bytes.NewReader(append(encoded, '\n')) // os/exec passes a pipe
	}
	err = cmd.Run()
	var exited *exec.ExitError
	if err != nil && !errors.As(err, &exited) {
		t.Fatal(err)
	}
	return cmd.ProcessState.ExitCode(), output.String()
}

func TestRegistrarRefusesWithoutInheritedCapabilities(t *testing.T) {
	// No configuration: os/exec gives the NUL device, not a pipe.
	if code, output := runRegistrarChild(t, nil, nil); code != 2 || !strings.Contains(output, "requires the engine's inherited pipes") {
		t.Fatalf("stray registrar ran: code %d, %q", code, output)
	}
	var events [3]windows.Handle
	for i := range events {
		h, err := windows.CreateEvent(nil, 0, 0, nil)
		must(t, err)
		defer windows.CloseHandle(h)
		must(t, windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT))
		events[i] = h
	}
	valid := registrarConfig{Version: registrarVersion, Capacity: MinCapacity, ViewBytes: uint64(viewBytes(MinCapacity)),
		Path:    `\\?\SWD#Wintun#{00000000-0000-0000-0000-000000000000}#{cac88484-7515-4c03-82e6-71a87aba61c3}`,
		Section: uint64(events[0]), Read: uint64(events[1]), Write: uint64(events[2])}
	inherit := []syscall.Handle{syscall.Handle(events[0]), syscall.Handle(events[1]), syscall.Handle(events[2])}
	for _, tc := range []struct {
		name, stage, text string
		edit              func(*registrarConfig)
		inherit           []syscall.Handle
	}{
		{"wrong version", "configuration", "unsupported", func(c *registrarConfig) { c.Version++ }, inherit},
		{"wrong view size", "configuration", "unsupported", func(c *registrarConfig) { c.ViewBytes += 4096 }, inherit},
		{"foreign device path", "configuration", "not a Wintun device", func(c *registrarConfig) { c.Path = `\\?\PhysicalDrive0` }, inherit},
		{"repeated handle", "inheritance", "not distinct", func(c *registrarConfig) { c.Read = c.Write }, inherit},
		{"event as section", "inheritance", `not "Section"`, func(*registrarConfig) {}, inherit},
		{"handles not inherited", "inheritance", "inherited handle", func(*registrarConfig) {}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := valid
			tc.edit(&config)
			code, output := runRegistrarChild(t, &config, tc.inherit)
			reply, err := parseReply([]byte(strings.TrimSpace(output)), nil)
			if code != 1 || err == nil || reply.Stage != tc.stage || !strings.Contains(reply.Error, tc.text) {
				t.Fatalf("code %d, reply %+v, err %v, output %q", code, reply, err, output)
			}
		})
	}
}

// ---- handle accounting ----

func handleSnapshot(t *testing.T) map[windows.Handle]bool {
	t.Helper()
	data := make([]uint64, 1<<17) // 1 MiB, pointer-aligned
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&data[0])), len(data)*8)
	var used uint32
	must(t, windows.NtQueryInformationProcess(windows.CurrentProcess(), windows.ProcessHandleInformation, unsafe.Pointer(&data[0]), uint32(len(raw)), &used))
	count := binary.LittleEndian.Uint64(raw[:8])
	if count > uint64((len(raw)-16)/40) {
		t.Fatal("invalid process handle snapshot")
	}
	values := map[windows.Handle]bool{}
	for i := uint64(0); i < count; i++ {
		values[windows.Handle(binary.LittleEndian.Uint64(raw[16+i*40:]))] = true
	}
	return values
}

func newHandleKinds(t *testing.T, before, after map[windows.Handle]bool) map[string]int {
	t.Helper()
	kinds := map[string]int{}
	for h := range after {
		if before[h] {
			continue
		}
		kind, err := objectType(h)
		if err != nil {
			kinds["unreadable"]++
			continue
		}
		if kind == "File" {
			fileType, err := windows.GetFileType(h)
			if err != nil {
				kinds["unreadable"]++
				continue
			}
			if fileType == windows.FILE_TYPE_PIPE {
				kind = "Pipe"
			}
		}
		kinds[kind]++
	}
	return kinds
}

// deviceFileGuard checks that the engine holds no registering device file.
// Only explicitly owned, lifetime-stable files get identity witnesses. Never
// duplicate a handle discovered in a snapshot: a concurrent close/reuse could
// turn even a successfully classified file into a socket before duplication.
// Native directory handles (including the OS's current-directory handle) are
// classified afresh without duplicating them. The independent native snapshot
// must be clean at construction and on every check; unknown baseline files are
// not silently grandfathered in.
type deviceFileGuard struct {
	files     map[windows.Handle]windows.Handle // known owned file -> identity witness
	witnesses map[windows.Handle]bool
}

func newDeviceFileGuard(t *testing.T) *deviceFileGuard {
	t.Helper()
	l, err := loadLibrary()
	must(t, err)
	g := &deviceFileGuard{files: map[windows.Handle]windows.Handle{}, witnesses: map[windows.Handle]bool{}}
	t.Cleanup(func() {
		for _, w := range g.files {
			if err := windows.CloseHandle(w); err != nil {
				t.Errorf("close device-file guard witness: %v", err)
			}
		}
	})
	// The library cache retains its file for process life. The serial test suite
	// also leaves the process's three os.File standard streams open. These are
	// known owners, not values borrowed from the snapshot. Pipes (including AFD
	// sockets) and unknown file types never get duplicated.
	for _, h := range []windows.Handle{windows.Handle(l.file.Fd()), windows.Handle(os.Stdin.Fd()), windows.Handle(os.Stdout.Fd()), windows.Handle(os.Stderr.Fd())} {
		if h == 0 || h == windows.InvalidHandle || g.files[h] != 0 {
			continue
		}
		fileType, err := windows.GetFileType(h)
		must(t, err)
		if fileType == windows.FILE_TYPE_PIPE {
			continue
		}
		if fileType != windows.FILE_TYPE_DISK && fileType != windows.FILE_TYPE_CHAR {
			t.Fatalf("device-file guard cannot witness unknown owned file type %#x (handle %#x)", fileType, h)
		}
		kind, err := objectType(h)
		must(t, err)
		if kind != "File" {
			t.Fatalf("device-file guard expected an owned File, found %q for %#x", kind, h)
		}
		w := witness(t, h)
		g.files[h], g.witnesses[w] = w, true
		if !sameObject(h, w) {
			t.Fatalf("device-file guard witness %#x does not identify owned file %#x", w, h)
		}
	}
	g.assertNone(t) // includes our witnesses; the baseline must actually be clean
	return g
}

// nativeDirectory queries FileStandardInfo, whose directory flag requires no
// particular file access rights (unlike FileBasicInfo/FILE_READ_ATTRIBUTES).
// This also works for the OS-owned current-directory handle. It reads no name
// and retains no handle value: a reused number must be classified again.
func nativeDirectory(h windows.Handle) bool {
	info, err := nativeFileStandardInfo(h)
	return err == nil && info.Directory != 0
}

// FILE_STANDARD_INFO uses one-byte BOOLEANs, not four-byte BOOLs. Both Windows
// targets have size 24, with DeletePending/Directory at offsets 20/21.
// https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_standard_info
type nativeFileStandard struct {
	AllocationSize, EndOfFile int64
	Links                     uint32
	DeletePending, Directory  uint8
	_                         [2]byte
}

func nativeFileStandardInfo(h windows.Handle) (nativeFileStandard, error) {
	var info nativeFileStandard
	err := windows.GetFileInformationByHandleEx(h, windows.FileStandardInfo, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	return info, err
}

// offenders returns every unowned/changed File except positively classified
// pipes and disk directories. A failed subtype/directory query is conservatively
// an offender, never an exclusion. unreadable counts failed object-type queries;
// either result makes the guard fail. Nothing here duplicates handles.
func (g *deviceFileGuard) offenders(t *testing.T) (offenders []windows.Handle, unreadable int) {
	t.Helper()
	for h := range handleSnapshot(t) {
		if g.witnesses[h] {
			continue // retained by this guard until t.Cleanup, never a session file
		}
		kind, err := objectType(h)
		if err != nil {
			unreadable++
			t.Logf("device-file guard cannot classify handle %#x: %v", h, err)
			continue
		}
		if kind != "File" {
			continue
		}
		if w, ok := g.files[h]; ok && sameObject(h, w) {
			continue
		}
		fileType, err := windows.GetFileType(h)
		if err == nil && fileType == windows.FILE_TYPE_PIPE {
			continue
		}
		if err == nil && fileType == windows.FILE_TYPE_DISK {
			info, infoErr := nativeFileStandardInfo(h)
			if infoErr == nil && info.Directory != 0 {
				continue
			}
			t.Logf("device-file guard disk %#x: standard=%+v standardError=%v", h, info, infoErr)
		}
		offenders = append(offenders, h)
	}
	return offenders, unreadable
}

func (g *deviceFileGuard) assertNone(t *testing.T) {
	t.Helper()
	offenders, unreadable := g.offenders(t)
	if len(offenders) != 0 || unreadable != 0 {
		// Keep unknown baseline files rejected, but make a hosted failure useful
		// without unsafe duplication or file-name queries. Windows/runtime-owned
		// files beyond the known owners must be evidenced before any exclusion.
		for _, h := range offenders {
			kind, kindErr := objectType(h)
			fileType, fileErr := windows.GetFileType(h)
			t.Logf("device-file guard offender %#x: object=%q objectError=%v fileType=%#x fileTypeError=%v", h, kind, kindErr, fileType, fileErr)
		}
		t.Fatalf("device-file guard is not clean: %d unowned/changed non-pipe or unclassified file handle(s) %v, %d unreadable handles", len(offenders), offenders, unreadable)
	}
}

// This is an evidence-gathering probe, not a replacement for the guard's hard
// negative control. Name queries can block inside a driver even after a pipe
// check (the borrowed number can be reused). Confine all such queries to one
// disposable child, bounded and reaped by the parent. Never copy the parent's
// snapshot handles into that child or duplicate/close any borrowed value.
func TestWintunRegistrarDeviceFileGuardDiagnostics(t *testing.T) {
	requireRunner(t)
	const childEnv = "NETSWITCH_WINTUN_DEVICE_GUARD_DIAGNOSTICS_CHILD"
	if os.Getenv(childEnv) != "1" {
		exe, err := os.Executable()
		must(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestWintunRegistrarDeviceFileGuardDiagnostics$", "-test.v", "-test.timeout=40s")
		cmd.Env = append(os.Environ(), childEnv+"=1")
		cmd.WaitDelay = 2 * time.Second
		var output bytes.Buffer
		cmd.Stdout, cmd.Stderr = &output, &output
		err = cmd.Run() // waits for exit and drains output, including after a timeout
		t.Logf("device-file diagnostic child (not a guard verdict):\n%s", output.String())
		if err != nil {
			t.Fatalf("device-file diagnostics incomplete: %v (deadline: %v)", err, ctx.Err())
		}
		return
	}

	_, err := loadLibrary()
	must(t, err)
	if unsafe.Sizeof(nativeFileStandard{}) != 24 || unsafe.Offsetof(nativeFileStandard{}.Directory) != 21 {
		t.Fatal("unexpected FILE_STANDARD_INFO layout")
	}
	dump := func(stage string, device windows.Handle) {
		t.Helper()
		var handles []windows.Handle
		for h := range handleSnapshot(t) {
			handles = append(handles, h)
		}
		slices.Sort(handles)
		files := 0
		foundDevice := device == 0
		for _, h := range handles {
			kind, err := objectType(h)
			if err != nil {
				t.Fatalf("diagnostic %s handle %#x object type: %v", stage, h, err)
			}
			if kind != "File" {
				continue
			}
			fileType, fileErr := windows.GetFileType(h)
			if fileErr == nil && fileType == windows.FILE_TYPE_PIPE {
				continue // never query pipe/socket names
			}
			files++
			foundDevice = foundDevice || h == device
			if files > 64 {
				t.Fatal("device-file diagnostics exceeded 64 non-pipe files")
			}
			// PUBLIC_OBJECT_BASIC_INFORMATION: attributes, granted access,
			// handle/pointer counts, then ten reserved ULONGs. No file I/O.
			var basic [14]uint32
			status, _, _ := ntQueryObject.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&basic[0])), unsafe.Sizeof(basic), 0)
			t.Logf("diagnostic %s handle=%#x actualDevice=%t fileType=%#x fileError=%v basicStatus=%#x attributes=%#x access=%#x handles=%d references=%d", stage, h, h == device, fileType, fileErr, status, basic[0], basic[1], basic[2], basic[3])
			if fileErr == nil && fileType == windows.FILE_TYPE_DISK {
				info, infoErr := nativeFileStandardInfo(h)
				t.Logf("diagnostic %s handle=%#x standard=%+v standardError=%v", stage, h, info, infoErr)
			}
			// The preceding line survives a hung query and identifies its handle.
			name, nameErr := diagnosticDeviceFileName(h)
			t.Logf("diagnostic %s handle=%#x nativeName=%q nameError=%v", stage, h, name, nameErr)
		}
		if !foundDevice {
			t.Fatalf("diagnostic %s missed the registered device %#x", stage, device)
		}
		t.Logf("diagnostic %s complete: %d non-pipe files", stage, files)
	}
	dump("loaded-library", 0)
	guid, err := windows.GenerateGUID()
	must(t, err)
	a, err := Create(Config{Name: "NsGuardCI", GUID: guid.String(), Capacity: MinCapacity})
	must(t, err)
	t.Cleanup(func() { must(t, a.Close()) })
	t.Logf("diagnostic adapter device path=%q", a.devicePath)
	dump("adapter-created", 0)
	s, err := a.startInProcessSession()
	must(t, err)
	defer s.Close()
	func() {
		s.mu.RLock()
		defer s.mu.RUnlock()
		o, ok := s.rings.owner.(*inProcessOwner)
		if !ok || !o.registered {
			t.Fatal("diagnostic never registered the real in-process device")
		}
		dump("in-process-registered", o.deviceOwner.Handle("diagnostic registered device"))
	}()
	must(t, s.Close())
	dump("in-process-closed", 0)
}

// Only the disposable diagnostic child above may query a borrowed file's name.
// The aligned buffer escapes through LazyProc.Call's //go:uintptrescapes with
// the conversion inline; it lives until the synchronous query returns or the
// entire child exits. No async I/O or goroutine can retain a retired buffer.
func diagnosticDeviceFileName(h windows.Handle) (string, error) {
	var buffer [1024]uint64 // one bounded 8 KiB OBJECT_NAME_INFORMATION query
	status, _, _ := ntQueryObject.Call(uintptr(h), 1, uintptr(unsafe.Pointer(&buffer[0])), unsafe.Sizeof(buffer), 0)
	if status != 0 {
		return "", windows.NTStatus(status)
	}
	info := (*windows.NTUnicodeString)(unsafe.Pointer(&buffer[0]))
	if info.Length == 0 {
		return "", nil
	}
	base, address := uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(info.Buffer))
	if info.Length%2 != 0 || info.Length > info.MaximumLength || address%2 != 0 || address < base+16 || address-base > unsafe.Sizeof(buffer) || uintptr(info.Length) > unsafe.Sizeof(buffer)-(address-base) {
		return "", errors.New("malformed diagnostic object name")
	}
	name := windows.UTF16ToString(unsafe.Slice(info.Buffer, int(info.Length/2)))
	runtime.KeepAlive(&buffer)
	return name, nil
}

func sessionRegistrar(t *testing.T, s *Session) (*registrar, windows.Handle) {
	t.Helper()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.rings == nil {
		t.Fatal("session has no rings")
	}
	g, ok := s.rings.owner.(*registrar)
	if !ok {
		t.Fatalf("session rings are owned by %T, not a registrar", s.rings.owner)
	}
	return g, witness(t, g.process.Handle("test registrar witness"))
}

func sessionView(t *testing.T, s *Session) uintptr {
	t.Helper()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.rings == nil {
		t.Fatal("session has no rings")
	}
	return s.rings.view
}

func exitState(process windows.Handle, wait time.Duration) (bool, uint32) {
	result, err := windows.WaitForSingleObject(process, uint32(wait/time.Millisecond))
	var code uint32
	windows.GetExitCodeProcess(process, &code)
	return err == nil && result == windows.WAIT_OBJECT_0, code
}

func exchange(t *testing.T, rounds int) {
	t.Helper()
	c := udpSocket(t)
	defer c.Close()
	reply := make([]byte, 2048)
	for round := range rounds {
		payload := bytes.Repeat([]byte{byte(round), 0x5a, 0xc3}, 200)
		must(t, c.SetDeadline(time.Now().Add(time.Second)))
		_, err := c.Write(payload)
		must(t, err)
		n, err := c.Read(reply)
		must(t, err)
		if !bytes.Equal(payload, reply[:n]) {
			t.Fatal("registrar session packet corruption")
		}
	}
}

// ---- production-size session, no device handle in the engine, mapping reclaim ----

func TestWintunRegistrarSession(t *testing.T) {
	requireRunner(t)
	_, err := loadLibrary() // the DLL's guarded image file is not a session handle
	must(t, err)
	warmRuntimeThreads()
	debug.FreeOSMemory()
	guard := newDeviceFileGuard(t)
	before := handleSnapshot(t) // guard witnesses are baseline handles, not session additions
	_, beforeBytes := processUsage(t)
	a := newAdapter(t, 0)
	f := fixtureOnAdapter(t, "ours", a)
	kinds := newHandleKinds(t, before, handleSnapshot(t))
	s := f.io.(*Session)
	_, process := sessionRegistrar(t, s)
	defer windows.CloseHandle(process)
	guard.assertNone(t)
	exchange(t, 64)
	f.stopEcho()
	if f.faults.Load() != 0 {
		t.Fatalf("registrar session packet path failed: %v", f.fault())
	}
	stats := s.Stats()
	view := sessionView(t, s)
	must(t, s.Close())
	exited, code := exitState(process, 0)
	closed := s.Stats().CloseDetails
	// The engine view must be reclaimed: unmapped, no longer section memory.
	var memory windows.MemoryBasicInformation
	must(t, windows.VirtualQuery(view, &memory, unsafe.Sizeof(memory)))
	if memory.State == windows.MEM_COMMIT || memory.Type == memMapped {
		t.Fatalf("engine ring view not reclaimed after close: state %#x type %#x", memory.State, memory.Type)
	}
	debug.FreeOSMemory()
	_, afterBytes := processUsage(t)
	// Re-registration on the same adapter proves the driver released it.
	again, err := a.StartSession()
	must(t, err)
	must(t, again.Close())
	report(t, map[string]any{"test": "registrar_session", "arch": runtime.GOARCH, "capacity": a.config.Capacity,
		"new_engine_handles": kinds, "registrar": stats.Registrar, "registrar_start_ms": float64(stats.Registrar.StartNanos) / 1e6,
		"read_waits": stats.ReadWaits, "read_wakes": stats.ReadWakes, "exchanges": 64,
		"view_state_after_close": memory.State, "view_type_after_close": memory.Type,
		"engine_private_delta_bytes": int64(afterBytes) - int64(beforeBytes),
		"registrar_exited":           exited, "registrar_exit_code": code,
		"retire_ms": float64(closed.DeviceNanos) / 1e6, "driver_wait_ms": float64(closed.DriverWaitNanos) / 1e6})
	if !stats.Registrar.FootprintMeasured || stats.Registrar.Starts != 1 || stats.Registrar.PID == 0 || stats.Registrar.PrivateBytes == 0 {
		t.Fatalf("registrar footprint not measured: %+v", stats.Registrar)
	}
	if !exited || code != 0 {
		t.Fatalf("registrar did not exit cleanly after Close: exited=%v code=%#x", exited, code)
	}
	if kinds["File"] != 0 || kinds["unreadable"] != 0 {
		t.Fatalf("session added a non-pipe file or unreadable handle to the engine: %v", kinds)
	}
	if int64(afterBytes)-int64(beforeBytes) > 16<<20 {
		t.Fatalf("engine retained %d bytes across a registrar session", int64(afterBytes)-int64(beforeBytes))
	}
}

// The device-file guard must be non-vacuous: the test-only in-process owner
// does hold a device file in this process, and the guard must detect it.
func TestWintunRegistrarDeviceFileGuardNegativeControl(t *testing.T) {
	requireRunner(t)
	a := newAdapter(t, MinCapacity)
	// Windows holds a directory File for the current working directory. Model
	// its limited access with another owned directory: it must be recognized by
	// native metadata, not copied into the guard's identity allowlist. The path
	// attributes independently establish that this fixture really is a directory.
	cwd, err := os.Getwd()
	must(t, err)
	name, err := windows.UTF16PtrFromString(cwd)
	must(t, err)
	attributes, err := windows.GetFileAttributes(name)
	must(t, err)
	if attributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		t.Fatal("guard directory fixture is not a directory")
	}
	directory, err := windows.CreateFile(name, windows.FILE_TRAVERSE|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	must(t, err)
	defer windows.CloseHandle(directory)
	if !handleSnapshot(t)[directory] || !nativeDirectory(directory) {
		t.Fatal("limited-access directory fixture is absent from the native handle table or cannot be classified")
	}
	guard := newDeviceFileGuard(t)
	s, err := a.startInProcessSession()
	must(t, err)
	defer s.Close()
	// Hold the actual owner stable while the independent native snapshot checks
	// it. A stray baseline file or one of the guard's witnesses cannot satisfy
	// this negative control. No removal runs here and no device is duplicated.
	func() {
		s.mu.RLock()
		defer s.mu.RUnlock() // native snapshot failure must not strand Close
		o, ok := s.rings.owner.(*inProcessOwner)
		if !ok || !o.registered {
			t.Fatal("negative control never registered the in-process device")
		}
		device := o.deviceOwner.Handle("test negative-control device identity")
		kind, typeErr := objectType(device)
		offenders, unreadable := guard.offenders(t)
		found, directoryFound := false, false
		for _, h := range offenders {
			found = found || h == device
			directoryFound = directoryFound || h == directory
		}
		report(t, map[string]any{"test": "device_file_guard_negative_control", "arch": runtime.GOARCH,
			"baseline_clean": true, "owned_file_witnesses": len(guard.files), "device_handles": len(offenders),
			"native_directory": uint64(directory), "directory_excluded": !directoryFound, "unreadable": unreadable,
			"registered_device": uint64(device), "actual_device_detected": found})
		if typeErr != nil || kind != "File" || unreadable != 0 || !found || directoryFound {
			t.Fatalf("guard did not distinguish the registered device %#x from directory %#x: kind=%q error=%v offenders=%v unreadable=%d", device, directory, kind, typeErr, offenders, unreadable)
		}
	}()
	must(t, s.Close())
	guard.assertNone(t)
}

// ---- session loss: distinct identity, clean teardown, no rebuild ----

type sessionLoss struct {
	session *Session
	reader  chan error
	guards  [][2]windows.Handle
	process windows.Handle
	devices *deviceFileGuard
}

func watchLoss(t *testing.T, s *Session, devices *deviceFileGuard) *sessionLoss {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	l := &sessionLoss{session: s, reader: make(chan error, 1), devices: devices}
	_, l.process = sessionRegistrar(t, s)
	t.Cleanup(func() { windows.CloseHandle(l.process) })
	waits := s.Stats().ReadWaits
	go func() {
		buf := make([]byte, MaxPacketSize)
		for {
			if _, err := s.ReadPacket(ctx, buf); err != nil {
				l.reader <- err
				return
			}
		}
	}()
	// Reader only: the loss must wake a parked reader without write traffic.
	for s.Stats().ReadWaits == waits {
		if ctx.Err() != nil {
			t.Fatal("reader never parked")
		}
		time.Sleep(time.Millisecond)
	}
	for range 32 {
		h := testEvent(t)
		l.guards = append(l.guards, [2]windows.Handle{h, witness(t, h)})
	}
	t.Cleanup(func() {
		for _, g := range l.guards {
			if sameObject(g[0], g[1]) {
				windows.CloseHandle(g[0])
			}
			windows.CloseHandle(g[1])
		}
	})
	// Before triggering the loss the engine must already hold no device file.
	l.devices.assertNone(t)
	return l
}

func (l *sessionLoss) wait(t *testing.T, ownerExit bool) error {
	t.Helper()
	var err error
	select {
	case err = <-l.reader:
	case <-time.After(10 * time.Second):
		t.Fatal("session loss left the reader parked")
	}
	if !errors.Is(err, ErrAdapterRemoved) || errors.Is(err, ErrRegistrarExited) != ownerExit {
		t.Fatalf("reader error %v: want ErrAdapterRemoved, owner-exit identity %v", err, ownerExit)
	}
	// The reader returns the settled reason only after maintenance has unlocked
	// the session. There is no concurrent writer in this fixture, so the native
	// loss must now have the same identity through WriteBatch as well.
	if n, writeErr := l.session.WriteBatch([][]byte{testPacket()}); n != 0 || !errors.Is(writeErr, ErrAdapterRemoved) || errors.Is(writeErr, ErrRegistrarExited) != ownerExit {
		t.Fatalf("writer after native loss: %d %v; want ErrAdapterRemoved, owner-exit identity %v", n, writeErr, ownerExit)
	}
	for i, g := range l.guards {
		if !sameObject(g[0], g[1]) || windows.SetEvent(g[0]) != nil {
			t.Fatalf("session loss closed or replaced unrelated engine handle %d", i)
		}
	}
	return err
}

var (
	locateDevNode      = windows.NewLazySystemDLL("cfgmgr32.dll").NewProc("CM_Locate_DevNodeW")
	queryAndRemoveTree = windows.NewLazySystemDLL("cfgmgr32.dll").NewProc("CM_Query_And_Remove_SubTreeW")
)

func queryRemove(t *testing.T, instance string) {
	t.Helper()
	id, err := windows.UTF16PtrFromString(instance)
	must(t, err)
	var node uint32
	if cr, _, _ := locateDevNode.Call(uintptr(unsafe.Pointer(&node)), uintptr(unsafe.Pointer(id)), 0); cr != 0 {
		t.Fatalf("CM_Locate_DevNode %s: CR %#x", instance, cr)
	}
	var veto uint32
	name := make([]uint16, 512)
	const removeUINotOK, removeNoRestart = 0x1, 0x2
	if cr, _, _ := queryAndRemoveTree.Call(uintptr(node), uintptr(unsafe.Pointer(&veto)), uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)), removeUINotOK|removeNoRestart); cr != 0 {
		t.Fatalf("query-remove refused: CR %#x, veto type %d by %q", cr, veto, windows.UTF16ToString(name))
	}
}

func TestWintunRegistrarOwnerChild(t *testing.T) {
	guid := os.Getenv("NETSWITCH_WINTUN_OWNER_GUID")
	if guid == "" {
		t.Skip("adapter owner child only")
	}
	requireRunner(t)
	a, err := Create(Config{Name: "NsRingOwnerCI", GUID: guid, Capacity: MinCapacity})
	must(t, err)
	fmt.Println("OWNER_READY " + a.InstanceID())
	for {
		time.Sleep(time.Hour)
	}
}

func readyLine(t *testing.T, cmd *exec.Cmd, prefix string) string {
	t.Helper()
	pipe, err := cmd.StdoutPipe()
	must(t, err)
	cmd.Stderr = os.Stderr
	must(t, cmd.Start())
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	found := make(chan string, 1)
	go func() {
		scan := bufio.NewScanner(pipe)
		for scan.Scan() {
			if strings.HasPrefix(scan.Text(), prefix) {
				found <- strings.TrimPrefix(scan.Text(), prefix)
				break
			}
		}
		close(found)
		for scan.Scan() { // keep draining
		}
	}()
	select {
	case line, ok := <-found:
		if !ok {
			t.Fatalf("child exited before %q", prefix)
		}
		return line
	case <-time.After(30 * time.Second):
		t.Fatalf("child did not report %q", prefix)
	}
	return ""
}

func mustGUID(t *testing.T, text string) windows.GUID {
	t.Helper()
	guid, err := windows.GUIDFromString(text)
	must(t, err)
	return guid
}

// Each loss ends the session through ErrAdapterRemoved without a recovery
// failure and without an automatic rebuild. Owner death carries the distinct
// ErrRegistrarExited and leaves the adapter usable; removal does not.
func TestWintunRegistrarLoss(t *testing.T) {
	requireRunner(t)
	for _, kind := range []string{"registrar-terminate", "job-terminate"} {
		t.Run(kind, func(t *testing.T) {
			a := newAdapter(t, MinCapacity)
			guard := newDeviceFileGuard(t)
			s, err := a.StartSession()
			must(t, err)
			defer s.Close()
			l := watchLoss(t, s, guard)
			g, w := sessionRegistrar(t, s)
			windows.CloseHandle(w)
			started := ticks()
			if kind == "job-terminate" {
				must(t, windows.TerminateJobObject(g.job.Handle("test job termination"), 0xdead))
			} else {
				must(t, windows.TerminateProcess(g.process.Handle("test registrar termination"), 0xdead))
			}
			err = l.wait(t, true)
			lost := elapsed(started)
			exited, code := exitState(l.process, time.Second)
			if !exited || code != 0xdead {
				t.Fatalf("registrar was not terminated: exited=%v code=%#x", exited, code)
			}
			must(t, s.Close())
			if stats := s.Stats(); stats.RecoveryFailures != 0 || stats.Recoveries != 0 {
				t.Fatalf("owner loss counted as recovery: %+v", stats)
			}
			if _, _, err := deviceForGUID(mustGUID(t, a.config.GUID)); err != nil {
				t.Fatalf("adapter disappeared with its registrar: %v", err)
			}
			f := fixtureOnAdapter(t, "ours", a)
			exchange(t, 16)
			f.stopEcho()
			report(t, map[string]any{"test": "registrar_loss", "arch": runtime.GOARCH, "kind": kind, "error": err.Error(),
				"reader_wake_ms": float64(lost) / float64(time.Millisecond), "guards_preserved": len(l.guards), "reregistered": true})
		})
	}
	t.Run("query-remove", func(t *testing.T) {
		a := newAdapter(t, MinCapacity)
		guard := newDeviceFileGuard(t)
		s, err := a.StartSession()
		must(t, err)
		defer s.Close()
		l := watchLoss(t, s, guard)
		started := ticks()
		queryRemove(t, a.InstanceID())
		err = l.wait(t, false) // real removal: adapter lost, but not owner death
		lost := elapsed(started)
		must(t, s.Close())
		exited, code := exitState(l.process, 0)
		if !exited || code != 0 {
			t.Fatalf("registrar did not exit on its stop request after removal: exited=%v code=%#x", exited, code)
		}
		instance := a.InstanceID()
		must(t, a.Close())
		assertPnPAbsent(t, instance)
		report(t, map[string]any{"test": "registrar_loss", "arch": runtime.GOARCH, "kind": "query-remove", "error": err.Error(),
			"reader_wake_ms": float64(lost) / float64(time.Millisecond), "guards_preserved": len(l.guards)})
	})
	t.Run("creator-death-surprise-removal", func(t *testing.T) {
		guid, err := windows.GenerateGUID()
		must(t, err)
		exe, err := os.Executable()
		must(t, err)
		owner := exec.Command(exe, "-test.run=^TestWintunRegistrarOwnerChild$", "-test.v")
		owner.Env = append(os.Environ(), "NETSWITCH_WINTUN_OWNER_GUID="+guid.String())
		instance := readyLine(t, owner, "OWNER_READY ")
		config := Config{Name: "NsRingOwnerCI", GUID: guid.String(), Capacity: MinCapacity}
		borrowed, err := Open(config)
		must(t, err)
		defer borrowed.Close()
		guard := newDeviceFileGuard(t)
		s, err := borrowed.StartSession()
		must(t, err)
		defer s.Close()
		l := watchLoss(t, s, guard)
		started := ticks()
		// The DLL ties the software device to its creator; the creator's death is
		// a surprise removal of a started device, not a query-remove.
		must(t, owner.Process.Kill())
		err = l.wait(t, false)
		lost := elapsed(started)
		must(t, s.Close())
		exited, code := exitState(l.process, 0)
		if !exited || code != 0 {
			t.Fatalf("registrar did not exit on its stop request after removal: exited=%v code=%#x", exited, code)
		}
		must(t, borrowed.Close())
		removed, cleanupErr := recoverAfterCrash(config)
		must(t, cleanupErr)
		assertPnPAbsent(t, instance)
		report(t, map[string]any{"test": "registrar_loss", "arch": runtime.GOARCH, "kind": "creator-death-surprise-removal",
			"error": err.Error(), "reader_wake_ms": float64(lost) / float64(time.Millisecond),
			"guards_preserved": len(l.guards), "phantoms_removed": removed})
	})
}

// After a ring-corruption recovery (which does spawn a fresh registrar), the
// engine must still hold no registering device file.
func TestWintunRegistrarNoDeviceFileThroughRecovery(t *testing.T) {
	requireRunner(t)
	a := newAdapter(t, MinCapacity)
	guard := newDeviceFileGuard(t)
	s, err := a.StartSession()
	must(t, err)
	defer s.Close()
	guard.assertNone(t)
	first := s.Stats().Registrar.PID
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, MaxPacketSize)
		for ctx.Err() == nil {
			if _, err := s.ReadPacket(ctx, buf); err != nil {
				return
			}
		}
	}()
	defer func() { cancel(); <-done }()
	before := s.Stats().Recoveries
	windows.SetEvent(s.wake)
	s.mu.Lock()
	injectRecoveryFault(s.rings)
	windows.SetEvent(s.rings.readEvent)
	windows.ResetEvent(s.wake)
	s.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for s.Stats().Recoveries == before {
		if time.Now().After(deadline) {
			t.Fatalf("corruption recovery did not complete: %+v", s.Stats())
		}
		time.Sleep(time.Millisecond)
	}
	guard.assertNone(t)
	second := s.Stats().Registrar.PID
	if s.Stats().Registrar.Starts < 2 || second == 0 {
		t.Fatalf("recovery did not start a fresh registrar: %+v", s.Stats().Registrar)
	}
	report(t, map[string]any{"test": "registrar_recovery_no_device_file", "arch": runtime.GOARCH,
		"first_registrar_pid": first, "second_registrar_pid": second, "registrar_starts": s.Stats().Registrar.Starts})
}

// ---- atomic job membership: parent crash before resume reaps the registrar ----

func TestWintunRegistrarJobReapsBeforeResume(t *testing.T) {
	exe, err := os.Executable()
	must(t, err)
	cmd := exec.Command(exe, registrarCrasherMode)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	must(t, err)
	stdout, err := cmd.StdoutPipe()
	must(t, err)
	must(t, cmd.Start())
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	var pid uint64
	scan := bufio.NewScanner(stdout)
	for scan.Scan() {
		if rest, ok := strings.CutPrefix(scan.Text(), "GRANDCHILD "); ok {
			pid, err = strconv.ParseUint(strings.TrimSpace(rest), 10, 32)
			must(t, err)
			break
		}
	}
	if pid == 0 {
		t.Fatal("crasher did not create a suspended registrar")
	}
	// Pin the grandchild PID so it cannot be recycled under the check.
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	must(t, err)
	defer windows.CloseHandle(h)
	if alive, _ := exitState(h, 0); alive {
		t.Fatal("suspended registrar already exited before the crash")
	}
	// Release the crasher, which exits without resuming and without closing the
	// job handle explicitly: process teardown closes it. The crasher deliberately
	// os.Exit(7)s, so Cmd.Wait returns that exact code, not success.
	stdin.Write([]byte("go\n"))
	stdin.Close()
	var exitErr *exec.ExitError
	if werr := cmd.Wait(); !errors.As(werr, &exitErr) || exitErr.ExitCode() != 7 {
		t.Fatalf("crasher did not exit with its sentinel code 7: %v", werr)
	}
	exited, code := exitState(h, 5*time.Second)
	if !exited {
		t.Fatal("suspended registrar outlived its crashed parent; job membership was not atomic")
	}
	report(t, map[string]any{"test": "registrar_job_reaps_before_resume", "arch": runtime.GOARCH,
		"grandchild_pid": pid, "grandchild_exit_code": code})
}

// ---- startup faults: resources released, no slow lock ----

func TestWintunRegistrarStartupFaults(t *testing.T) {
	// A non-device path: these faults exercise validation, reply and timeout
	// paths without a registration, so they need no adapter. Post-registration
	// failure cleanup is proven separately against a real device.
	path := `\\?\SWD#Wintun#{00000000-0000-0000-0000-000000000000}#{cac88484-7515-4c03-82e6-71a87aba61c3}`
	for _, tc := range []struct {
		name, fault, text string
		shortTimeout      bool
	}{
		{"pre-reply exit", "pre-reply-exit", "gave no reply", false},
		{"wrong pid", "wrong-pid", "reported process", false},
		{"hang to timeout", "hang", "did not report", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restoreCmd, restoreEnv := registrarCommand, registrarExtraEnv
			restoreTimeout, restoreResume := registrarStartTimeout, registrarBeforeResume
			registrarCommand = registrarFixtureMode
			registrarExtraEnv = []string{"NETSWITCH_WINTUN_FIXTURE_FAULT=" + tc.fault}
			if tc.shortTimeout {
				registrarStartTimeout = time.Second
			}
			// Independently witness the child's death: pin its process handle
			// before resume so the number cannot be recycled under the check.
			var child windows.Handle
			registrarBeforeResume = func(pid uint32) {
				if h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid); err == nil {
					child = h
				}
			}
			defer func() {
				registrarCommand, registrarExtraEnv = restoreCmd, restoreEnv
				registrarStartTimeout, registrarBeforeResume = restoreTimeout, restoreResume
				if child != 0 {
					windows.CloseHandle(child)
				}
			}()
			warmRuntimeThreads()
			debug.FreeOSMemory()
			before := handleSnapshot(t)
			r, err := allocateRings(MinCapacity)
			must(t, err)
			if err := r.createEvents(); err != nil {
				t.Fatal(errors.Join(err, r.close()))
			}
			view := r.view
			start := time.Now()
			g, err := startRegistrar(path, r)
			elapsedStart := time.Since(start)
			if g != nil {
				t.Fatal("a faulty registrar must not yield a session owner")
			}
			if err == nil || !strings.Contains(err.Error(), tc.text) {
				t.Fatalf("fault %q gave error %v", tc.fault, err)
			}
			if child == 0 {
				t.Fatal("before-resume hook never captured the child process")
			}
			childExited, childCode := exitState(child, 5*time.Second)
			if !childExited {
				t.Fatalf("startup fault %q left the child process alive", tc.fault)
			}
			childCloseErr := windows.CloseHandle(child)
			child = 0 // consume the independent witness before the leak snapshot
			must(t, childCloseErr)
			must(t, r.close())
			// The engine's mapped view must be reclaimed on a startup failure too.
			var memory windows.MemoryBasicInformation
			must(t, windows.VirtualQuery(view, &memory, unsafe.Sizeof(memory)))
			if memory.State == windows.MEM_COMMIT || memory.Type == memMapped {
				t.Fatalf("startup fault %q left the ring view mapped: state %#x type %#x", tc.fault, memory.State, memory.Type)
			}
			debug.FreeOSMemory()
			kinds := newHandleKinds(t, before, handleSnapshot(t))
			for _, leaked := range []string{"Section", "Job", "File", "Pipe", "Process", "Event", "unreadable"} {
				if kinds[leaked] != 0 {
					t.Fatalf("startup fault %q leaked %s handles: %v", tc.fault, leaked, kinds)
				}
			}
			if elapsedStart > registrarStartTimeout+registrarKillTimeout+5*time.Second {
				t.Fatalf("startup fault %q took %v; no fast failure", tc.fault, elapsedStart)
			}
			report(t, map[string]any{"test": "registrar_startup_fault", "arch": runtime.GOARCH, "fault": tc.fault,
				"error": err.Error(), "elapsed_ms": elapsedStart.Milliseconds(), "child_exit_code": childCode,
				"view_state_after_close": memory.State, "leaked_handles": kinds})
		})
	}
}

// With a real adapter, a registrar that registers the device and then dies
// before replying leaves an orphaned registration. The driver releases it when
// the process ends, so StartSession fails but a fresh session then succeeds and
// the engine never held a device file.
func TestWintunRegistrarPostRegisterFailureCleanup(t *testing.T) {
	requireRunner(t)
	a := newAdapter(t, MinCapacity)
	guard := newDeviceFileGuard(t)
	restoreCmd, restoreEnv, restoreResume := registrarCommand, registrarExtraEnv, registrarBeforeResume
	var child windows.Handle
	var witnessErr error
	defer func() {
		registrarCommand, registrarExtraEnv, registrarBeforeResume = restoreCmd, restoreEnv, restoreResume
		if child != 0 {
			windows.CloseHandle(child)
		}
	}()
	registrarCommand = registrarFixtureMode
	registrarExtraEnv = []string{"NETSWITCH_WINTUN_FIXTURE_FAULT=post-register-exit"}
	registrarBeforeResume = func(pid uint32) {
		child, witnessErr = windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	}
	s, startErr := a.StartSession()
	registrarCommand, registrarExtraEnv, registrarBeforeResume = restoreCmd, restoreEnv, restoreResume
	if startErr == nil {
		s.Close()
		t.Fatal("a registrar that died after registering must fail StartSession")
	}
	if witnessErr != nil || child == 0 {
		t.Fatalf("post-register fixture process was not independently witnessed: %v", witnessErr)
	}
	exited, code := exitState(child, time.Second)
	// Exit 6 is reachable only after registerDevice succeeded. A validation or
	// registration failure exits 1 and must not masquerade as cleanup proof.
	if !exited || code != 6 {
		t.Fatalf("fixture did not reach post-registration exit 6: exited=%v code=%#x startup=%v", exited, code, startErr)
	}
	childCloseErr := windows.CloseHandle(child)
	child = 0
	must(t, childCloseErr)
	guard.assertNone(t)
	// The orphaned registration must be gone: a fresh real session now succeeds
	// on the same adapter and carries traffic.
	f := fixtureOnAdapter(t, "ours", a)
	exchange(t, 16)
	f.stopEcho()
	if f.faults.Load() != 0 {
		t.Fatalf("recovered session failed: %v", f.fault())
	}
	report(t, map[string]any{"test": "registrar_post_register_failure", "arch": runtime.GOARCH,
		"startup_error": startErr.Error(), "registered_child_exit_code": code, "recovered": true})
}

// ---- engine crash proves kill-on-close, with a helper that ignores EOF ----

func TestWintunRegistrarEngineHolderChild(t *testing.T) {
	if os.Getenv("NETSWITCH_WINTUN_ENGINE_HOLDER") == "" {
		t.Skip("engine holder child only")
	}
	registrarCommand = registrarFixtureMode
	registrarExtraEnv = []string{"NETSWITCH_WINTUN_FIXTURE_FAULT=block"} // the registrar never reads its control pipe
	r, err := allocateRings(MinCapacity)
	must(t, err)
	must(t, r.createEvents())
	g, err := startRegistrar(`\\?\SWD#Wintun#{00000000-0000-0000-0000-000000000000}#{cac88484-7515-4c03-82e6-71a87aba61c3}`, r)
	must(t, err)
	fmt.Printf("HOLDER_READY %d\n", g.reply.PID)
	for {
		time.Sleep(time.Hour)
	}
}

// Killing the engine closes the only job handle. Because the registrar ignores
// its control pipe, pipe EOF cannot reap it: only kill-on-close can, which is
// exactly what this proves.
func TestWintunRegistrarEngineCrash(t *testing.T) {
	exe, err := os.Executable()
	must(t, err)
	engine := exec.Command(exe, "-test.run=^TestWintunRegistrarEngineHolderChild$", "-test.v")
	engine.Env = append(os.Environ(), "NETSWITCH_WINTUN_ENGINE_HOLDER=1")
	pid, err := strconv.ParseUint(readyLine(t, engine, "HOLDER_READY "), 10, 32)
	must(t, err)
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	must(t, err)
	defer windows.CloseHandle(h)
	name := make([]uint16, 4096)
	size := uint32(len(name))
	must(t, windows.QueryFullProcessImageName(h, 0, &name[0], &size))
	if !strings.EqualFold(windows.UTF16ToString(name[:size]), exe) {
		t.Fatalf("PID %d is %q, not the registrar image", pid, windows.UTF16ToString(name[:size]))
	}
	if exited, _ := exitState(h, 0); exited {
		t.Fatal("registrar exited before the engine crash")
	}
	started := ticks()
	must(t, engine.Process.Kill())
	exited, code := exitState(h, 5*time.Second)
	died := elapsed(started)
	if !exited {
		t.Fatal("registrar that ignores EOF outlived the crashed engine; kill-on-close did not fire")
	}
	report(t, map[string]any{"test": "registrar_engine_crash", "arch": runtime.GOARCH, "registrar_pid": pid,
		"registrar_exit_code": code, "registrar_exit_after_engine_kill_ms": float64(died) / float64(time.Millisecond)})
}
