//go:build windows

package wintun

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/winclock"
	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

// The Wintun 0.14.1 driver can itself close the registering handle to its
// device during removal, by numeric value in the holding process. A process
// that also opens and closes other handles cannot prove
// that a value it later closes, or that the driver closes, still names the
// object it opened. So the registration's device handle lives only in a
// registrar: a hidden mode of the same signed executable that opens the
// device once, registers rings in a shared section, and then only waits.
// It never closes, reuses or touches that value again; process teardown owns
// it, and the driver's handle-close cleanup then releases the rings.
//
// The registrar receives exactly five inherited handles through an explicit
// list: its control pipe (stdin), its reply pipe (stdout and stderr), the
// unnamed ring section and the two unnamed ring events. It is created
// suspended and assigned to its own unnamed kill-on-close job before it runs.
// Only the engine holds that job handle, so an engine crash ends the job and
// the registrar with it. No kernel object is named.

// RegistrarMode is the hidden argument for the registrar. Every program that
// starts sessions (the engine, TestISP and test binaries) dispatches it before
// anything else: if len(os.Args) == 2 && os.Args[1] == wintun.RegistrarMode,
// it calls os.Exit(wintun.RunRegistrar()).
const RegistrarMode = "__netswitch-wintun-registrar"

// registrarCommand is a test seam: the package's own tests substitute a
// fixture mode of the same test binary. Production always uses RegistrarMode.
var registrarCommand = RegistrarMode

const (
	registrarVersion      = 1
	registrarReplyPrefix  = "WINTUN_REGISTRAR "
	registrarMessageLimit = 8 << 10
	registrarStartTimeout = 15 * time.Second
	registrarStopTimeout  = 2 * time.Second
	registrarKillTimeout  = 5 * time.Second
	wintunInterfacePrefix = `\\?\SWD#WINTUN#`
	memMapped             = 0x40000 // MEMORY_BASIC_INFORMATION.Type for a section view
)

var errRegistrarAlive = errors.New("Wintun registrar did not exit")

// registrarConfig carries the child-side values of the inherited handles and
// the device interface path the engine already verified against the adapter
// GUID. The pipe is anonymous and its only writer is the engine.
type registrarConfig struct {
	Version   int    `json:"version"`
	Path      string `json:"path"`
	Capacity  uint32 `json:"capacity"`
	ViewBytes uint64 `json:"viewBytes"`
	Section   uint64 `json:"section"`
	Read      uint64 `json:"read"`
	Write     uint64 `json:"write"`
}

type registrarReply struct {
	PID          uint32 `json:"pid"`
	Ready        bool   `json:"ready"`
	Stage        string `json:"stage,omitempty"`
	Errno        uint32 `json:"errno,omitempty"`
	Error        string `json:"error,omitempty"`
	Address      uint64 `json:"address,omitempty"`
	MemoryType   uint32 `json:"memoryType,omitempty"`
	Handles      uint32 `json:"handles,omitempty"`
	PrivateBytes uint64 `json:"privateBytes,omitempty"`
	HeapBytes    uint64 `json:"heapBytes,omitempty"`
	StackBytes   uint64 `json:"stackBytes,omitempty"`
}

// RegistrarStats describes the latest registrar of a session. The process
// figures are its own measurements at registration time.
type RegistrarStats struct {
	Starts       uint64 // registrars started by this session, including recoveries
	PID          uint32
	StartNanos   uint64 // CreateProcess through the ready reply
	Handles      uint32
	PrivateBytes uint64
	HeapBytes    uint64
	StackBytes   uint64
}

type registrar struct {
	process, job, control winhandle.Owner
	reply                 registrarReply
	startNanos            uint64
}

func (g *registrar) exited() windows.Handle {
	return g.process.Handle("Wintun registrar exit wait")
}

func (g *registrar) wait(timeout time.Duration) bool {
	result, err := windows.WaitForSingleObject(g.process.Handle("Wintun registrar join"), uint32(timeout/time.Millisecond))
	return err == nil && result == windows.WAIT_OBJECT_0
}

func (g *registrar) exitCode() uint32 {
	var code uint32
	if windows.GetExitCodeProcess(g.process.Handle("Wintun registrar exit code"), &code) != nil {
		return ^uint32(0)
	}
	return code
}

// retire requests exit by closing the control pipe's only writer, then
// terminates the job if the registrar does not exit. Closing the job handle
// would also terminate it, through kill-on-close.
func (g *registrar) retire(closeHandle func(windows.Handle) error) (bool, error) {
	err := g.control.Close("Wintun registrar control close", closeHandle)
	exited := g.wait(registrarStopTimeout)
	if !exited {
		err = errors.Join(err, windows.TerminateJobObject(g.job.Handle("Wintun registrar termination"), 1))
		exited = g.wait(registrarKillTimeout)
	}
	err = errors.Join(err, g.job.Close("Wintun registrar job close", closeHandle),
		g.process.Close("Wintun registrar process close", closeHandle))
	if !exited {
		err = errors.Join(err, errRegistrarAlive)
	}
	return exited, err
}

func (g *registrar) end(r *rings, closeHandle func(windows.Handle) error) (bool, error) {
	started := winclock.Now()
	exited, err := g.retire(closeHandle)
	r.closeProfile.DeviceNanos = uint64(winclock.Since(started))
	if exited {
		// Handle-table rundown precedes the process signal, so the driver's
		// cleanup has normally published both markers already.
		started = winclock.Now()
		if !r.awaitRelease() {
			err = errors.Join(err, errRegistrationHeld)
		}
		r.closeProfile.DriverWaitNanos = uint64(winclock.Since(started))
	}
	return false, err
}

func (g *registrar) stats(starts uint64) RegistrarStats {
	return RegistrarStats{Starts: starts, PID: g.reply.PID, StartNanos: g.startNanos, Handles: g.reply.Handles,
		PrivateBytes: g.reply.PrivateBytes, HeapBytes: g.reply.HeapBytes, StackBytes: g.reply.StackBytes}
}

// registrarEnvironment keeps the helper's runtime small and deterministic. It
// inherits nothing else from the engine's environment.
func registrarEnvironment() (*uint16, error) {
	entries := []string{"GOMAXPROCS=1", "GOGC=50", "GOMEMLIMIT=8MiB"}
	if root := os.Getenv("SystemRoot"); root != "" {
		entries = append(entries, "SystemRoot="+root)
	}
	var block []uint16
	for _, entry := range entries {
		encoded, err := windows.UTF16FromString(entry)
		if err != nil {
			return nil, err
		}
		block = append(block, encoded...)
	}
	block = append(block, 0)
	return &block[0], nil
}

func startRegistrar(path string, r *rings) (_ *registrar, err error) {
	if r.section.IsZero() || r.readOwner.IsZero() || r.writeOwner.IsZero() {
		return nil, errors.New("Wintun registrar requires a ring section and both ring events")
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	pipe := func(site string) (read, write winhandle.Owner, err error) {
		var a, b windows.Handle
		if err = windows.CreatePipe(&a, &b, nil, 0); err != nil {
			return read, write, fmt.Errorf("%s: %w", site, err)
		}
		return winhandle.Open(a, site+" read open"), winhandle.Open(b, site+" write open"), nil
	}
	var owned []winhandle.Owner // closed on any failure before the registrar is returned
	closeOwned := func() error {
		var err error
		for i := len(owned) - 1; i >= 0; i-- {
			err = errors.Join(err, owned[i].HandleClose("Wintun registrar setup close"))
		}
		owned = nil
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, closeOwned())
		}
	}()
	controlRead, controlWrite, err := pipe("Wintun registrar control pipe")
	if err != nil {
		return nil, err
	}
	owned = append(owned, controlRead, controlWrite)
	replyRead, replyWrite, err := pipe("Wintun registrar reply pipe")
	if err != nil {
		return nil, err
	}
	owned = append(owned, replyRead, replyWrite)
	h, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	job := winhandle.Open(h, "Wintun registrar job open")
	owned = append(owned, job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
				windows.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
			ActiveProcessLimit: 1,
		},
	}
	if _, err = windows.SetInformationJobObject(job.Handle("Wintun registrar job limits"), windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return nil, fmt.Errorf("limit Wintun registrar job: %w", err)
	}
	ui := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: windows.JOB_OBJECT_UILIMIT_DESKTOP |
		windows.JOB_OBJECT_UILIMIT_DISPLAYSETTINGS | windows.JOB_OBJECT_UILIMIT_EXITWINDOWS |
		windows.JOB_OBJECT_UILIMIT_GLOBALATOMS | windows.JOB_OBJECT_UILIMIT_HANDLES |
		windows.JOB_OBJECT_UILIMIT_READCLIPBOARD | windows.JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS |
		windows.JOB_OBJECT_UILIMIT_WRITECLIPBOARD}
	if _, err = windows.SetInformationJobObject(job.Handle("Wintun registrar UI limits"), windows.JobObjectBasicUIRestrictions,
		uintptr(unsafe.Pointer(&ui)), uint32(unsafe.Sizeof(ui))); err != nil {
		return nil, fmt.Errorf("limit Wintun registrar UI access: %w", err)
	}
	// Inheritable duplicates exist only until CreateProcess returns, and only
	// the explicit handle list below can pass them. The job, the process and
	// the engine's pipe ends are never inheritable.
	sources := []winhandle.Owner{controlRead, replyWrite, r.section, r.readOwner, r.writeOwner}
	inherited := make([]windows.Handle, 0, len(sources))
	defer func() {
		for _, h := range inherited {
			windows.CloseHandle(h)
		}
	}()
	for _, source := range sources {
		var h windows.Handle
		if err = windows.DuplicateHandle(windows.CurrentProcess(), source.Handle("Wintun registrar inheritance source"),
			windows.CurrentProcess(), &h, 0, true, windows.DUPLICATE_SAME_ACCESS); err != nil {
			return nil, err
		}
		inherited = append(inherited, h)
	}
	config, err := json.Marshal(registrarConfig{Version: registrarVersion, Path: path, Capacity: r.send.capacity,
		ViewBytes: uint64(viewBytes(r.send.capacity)), Section: uint64(inherited[2]), Read: uint64(inherited[3]), Write: uint64(inherited[4])})
	if err != nil {
		return nil, err
	}
	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return nil, err
	}
	defer attrs.Delete()
	if err = attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&inherited[0]), uintptr(len(inherited))*unsafe.Sizeof(inherited[0])); err != nil {
		return nil, err
	}
	si := windows.StartupInfoEx{StartupInfo: windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{})),
		Flags: windows.STARTF_USESTDHANDLES, StdInput: inherited[0], StdOutput: inherited[1], StdErr: inherited[1]},
		ProcThreadAttributeList: attrs.List()}
	app, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return nil, err
	}
	commandLine, err := windows.UTF16PtrFromString(windows.EscapeArg(exe) + " " + windows.EscapeArg(registrarCommand))
	if err != nil {
		return nil, err
	}
	environment, err := registrarEnvironment()
	if err != nil {
		return nil, err
	}
	started := winclock.Now()
	var pi windows.ProcessInformation
	// DETACHED_PROCESS: the registrar needs no console; its I/O is the two pipes.
	if err = windows.CreateProcess(app, commandLine, nil, nil, true,
		windows.CREATE_SUSPENDED|windows.DETACHED_PROCESS|windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_UNICODE_ENVIRONMENT,
		environment, nil, &si.StartupInfo, &pi); err != nil {
		return nil, fmt.Errorf("start Wintun registrar: %w", err)
	}
	for _, h := range inherited {
		windows.CloseHandle(h)
	}
	inherited = inherited[:0]
	process := winhandle.Open(pi.Process, "Wintun registrar process open")
	thread := winhandle.Open(pi.Thread, "Wintun registrar thread open")
	g := &registrar{process: process, job: job, control: controlWrite}
	// From here a failure must end the suspended or running registrar before
	// any of its handles close: it may already hold a registration.
	abandon := func(cause error) error {
		// Before job assignment only TerminateProcess reaches it; afterwards
		// either does. An already-exited process makes these calls no-ops.
		windows.TerminateJobObject(job.Handle("Wintun registrar setup termination"), 1)
		windows.TerminateProcess(process.Handle("Wintun registrar setup process termination"), 1)
		var err error
		if !g.wait(registrarKillTimeout) {
			err = errRegistrarAlive
		}
		return errors.Join(cause, err, process.HandleClose("Wintun registrar setup process close"))
	}
	if err = windows.AssignProcessToJobObject(job.Handle("Wintun registrar job assignment"), process.Handle("Wintun registrar job assignment")); err != nil {
		thread.HandleClose("Wintun registrar thread close")
		return nil, abandon(fmt.Errorf("assign Wintun registrar job: %w", err))
	}
	_, err = windows.ResumeThread(thread.Handle("Wintun registrar resume"))
	err = errors.Join(err, thread.HandleClose("Wintun registrar thread close"))
	if err != nil {
		return nil, abandon(err)
	}
	// The registrar now holds the only other ends of both pipes. Its exit
	// therefore ends the reply read below.
	err = errors.Join(controlRead.HandleClose("Wintun registrar control read close"), replyWrite.HandleClose("Wintun registrar reply write close"))
	owned = []winhandle.Owner{replyRead, controlWrite, job}
	if err != nil {
		return nil, abandon(err)
	}
	var written uint32
	message := append(config, '\n')
	if err = windows.WriteFile(controlWrite.Handle("Wintun registrar configuration"), message, &written, nil); err == nil && int(written) != len(message) {
		err = errors.New("short Wintun registrar configuration write")
	}
	if err != nil {
		return nil, abandon(fmt.Errorf("configure Wintun registrar: %w", err))
	}
	type result struct {
		output []byte
		err    error
	}
	read := make(chan result, 1)
	go func() {
		output, err := readLine(replyRead.Handle("Wintun registrar reply"), registrarMessageLimit)
		read <- result{output, err}
	}()
	timer := time.NewTimer(registrarStartTimeout)
	var reply result
	select {
	case reply = <-read:
		timer.Stop()
	case <-timer.C:
		// Ending the registrar ends the pending pipe read before its handle closes.
		cause := abandon(fmt.Errorf("Wintun registrar did not report within %v", registrarStartTimeout))
		select {
		case <-read:
		case <-time.After(registrarKillTimeout):
			// The reader may still issue ReadFile on this value: never close it.
			owned = []winhandle.Owner{controlWrite, job}
		}
		return nil, cause
	}
	g.reply, err = parseReply(reply.output, reply.err)
	if err == nil && g.reply.PID != pi.ProcessId {
		err = fmt.Errorf("Wintun registrar reported process %d, started %d", g.reply.PID, pi.ProcessId)
	}
	if err != nil {
		exited := g.wait(registrarStopTimeout)
		cause := err
		if exited {
			cause = fmt.Errorf("%w (registrar exit code %#x)", err, g.exitCode())
		}
		return nil, abandon(cause)
	}
	g.startNanos = uint64(winclock.Since(started))
	if err = replyRead.HandleClose("Wintun registrar reply read close"); err != nil {
		owned = []winhandle.Owner{controlWrite, job}
		return nil, abandon(err)
	}
	owned = nil
	return g, nil
}

// readLine reads one newline-terminated message without buffering beyond it.
func readLine(h windows.Handle, limit int) ([]byte, error) {
	var output []byte
	var chunk [512]byte
	for len(output) < limit {
		var n uint32
		err := windows.ReadFile(h, chunk[:], &n, nil)
		output = append(output, chunk[:n]...)
		if i := bytes.IndexByte(output, '\n'); i >= 0 {
			return output[:i], nil
		}
		if err != nil || n == 0 {
			return output, err
		}
	}
	return output, fmt.Errorf("Wintun registrar message exceeds %d bytes", limit)
}

func parseReply(output []byte, readErr error) (registrarReply, error) {
	var reply registrarReply
	text := string(output)
	if !strings.HasPrefix(text, registrarReplyPrefix) {
		// A runtime failure writes plain text to the same pipe; keep it.
		return reply, fmt.Errorf("Wintun registrar gave no reply (%v): %q", readErr, text)
	}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(text, registrarReplyPrefix)), &reply); err != nil {
		return reply, fmt.Errorf("invalid Wintun registrar reply %q: %w", text, err)
	}
	if !reply.Ready {
		cause := errors.New(reply.Error)
		if reply.Errno != 0 {
			cause = fmt.Errorf("%s: %w", reply.Error, windows.Errno(reply.Errno))
		}
		return reply, fmt.Errorf("Wintun registrar %s: %w", reply.Stage, cause)
	}
	if reply.MemoryType != memMapped {
		return reply, fmt.Errorf("Wintun registrar view is not section memory (%#x)", reply.MemoryType)
	}
	return reply, nil
}

// RunRegistrar is the hidden registrar mode. It returns the process exit code.
// It refuses to run unless both standard handles are pipes and the expected
// inherited section and events are present, of the right object types.
func RunRegistrar() int { return runRegistrar(registerDevice) }

// registerDevice opens the device once and registers the rings. It has no
// close path: process teardown closes the handle, and the driver may close it
// earlier during removal. The value is never used again after this call.
func registerDevice(path string, desc *registration) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	device, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return fmt.Errorf("open Wintun device: %w", err)
	}
	var returned uint32
	if err := windows.DeviceIoControl(device, registerRingsIOCTL, (*byte)(unsafe.Pointer(desc)), uint32(unsafe.Sizeof(*desc)), nil, 0, &returned, nil); err != nil {
		return fmt.Errorf("register Wintun rings: %w", err)
	}
	return nil
}

func isPipe(h windows.Handle) bool {
	kind, err := windows.GetFileType(h)
	return err == nil && kind == windows.FILE_TYPE_PIPE
}

func runRegistrar(register func(string, *registration) error) int {
	stdin, inErr := windows.GetStdHandle(windows.STD_INPUT_HANDLE)
	stdout, outErr := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if inErr != nil || outErr != nil || !isPipe(stdin) || !isPipe(stdout) {
		fmt.Fprintln(os.Stderr, "netswitch: internal Wintun registrar mode requires the engine's inherited pipes")
		return 2
	}
	send := func(reply registrarReply) {
		reply.PID = windows.GetCurrentProcessId()
		encoded, _ := json.Marshal(reply)
		message := append([]byte(registrarReplyPrefix), encoded...)
		message = append(message, '\n')
		var written uint32
		windows.WriteFile(stdout, message, &written, nil)
	}
	fail := func(stage string, err error) int {
		reply := registrarReply{Stage: stage, Error: err.Error()}
		var errno windows.Errno
		if errors.As(err, &errno) {
			reply.Errno = uint32(errno)
		}
		send(reply)
		return 1
	}
	line, err := readLine(stdin, registrarMessageLimit)
	if err != nil {
		return fail("configuration", err)
	}
	var config registrarConfig
	if err := json.Unmarshal(line, &config); err != nil {
		return fail("configuration", err)
	}
	if config.Version != registrarVersion || !validCapacity(config.Capacity) || config.ViewBytes != uint64(viewBytes(config.Capacity)) {
		return fail("configuration", errors.New("unsupported registrar configuration"))
	}
	if !strings.HasPrefix(strings.ToUpper(config.Path), wintunInterfacePrefix) || strings.ContainsRune(config.Path, 0) {
		return fail("configuration", errors.New("not a Wintun device interface path"))
	}
	section, read, write := windows.Handle(config.Section), windows.Handle(config.Read), windows.Handle(config.Write)
	if section == read || section == write || read == write {
		return fail("inheritance", errors.New("registrar handles are not distinct"))
	}
	for _, want := range []struct {
		h    windows.Handle
		kind string
	}{{section, "Section"}, {read, "Event"}, {write, "Event"}} {
		kind, err := objectType(want.h)
		if err != nil {
			return fail("inheritance", fmt.Errorf("inherited handle %#x: %w", want.h, err))
		}
		if kind != want.kind {
			return fail("inheritance", fmt.Errorf("inherited handle %#x is %q, not %q", want.h, kind, want.kind))
		}
	}
	size := uintptr(config.ViewBytes)
	view, err := windows.MapViewOfFile(section, windows.FILE_MAP_READ|windows.FILE_MAP_WRITE, 0, 0, size)
	if err != nil {
		return fail("map", err)
	}
	var memory windows.MemoryBasicInformation
	if err := windows.VirtualQuery(view, &memory, unsafe.Sizeof(memory)); err != nil {
		return fail("map", err)
	}
	if memory.Type != memMapped || memory.RegionSize < size {
		return fail("map", fmt.Errorf("inherited section view type %#x, %d bytes", memory.Type, memory.RegionSize))
	}
	data := mappedSlice(view, int(size))
	rb := ringBytes(config.Capacity)
	desc := registration{
		Send:    ringRegistration{uint32(rb), &data[0], read},
		Receive: ringRegistration{uint32(rb), &data[rb], write},
	}
	if err := register(config.Path, &desc); err != nil {
		return fail("register", err)
	}
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	handles, private := registrarUsage()
	send(registrarReply{Ready: true, Address: uint64(view), MemoryType: memory.Type, Handles: handles,
		PrivateBytes: private, HeapBytes: stats.HeapAlloc, StackBytes: stats.StackInuse})
	// Wait for the control pipe's EOF: the engine's stop request, or its exit.
	var chunk [64]byte
	for {
		var n uint32
		if err := windows.ReadFile(stdin, chunk[:], &n, nil); err != nil || n == 0 {
			return 0
		}
	}
}

var (
	ntQueryObject         = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryObject")
	getProcessHandleCount = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessHandleCount")
	getProcessMemoryInfo  = windows.NewLazySystemDLL("kernel32.dll").NewProc("K32GetProcessMemoryInfo")
)

// objectType reads the kernel object type name through ObjectTypeInformation.
// Unlike name queries, a type query never waits on a synchronous file.
func objectType(h windows.Handle) (string, error) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		return "", errors.New("object type query requires a 64-bit process")
	}
	var buffer [128]uint64 // pointer-aligned OBJECT_TYPE_INFORMATION
	var returned uint32
	status, _, _ := ntQueryObject.Call(uintptr(h), 2, uintptr(unsafe.Pointer(&buffer[0])), unsafe.Sizeof(buffer), uintptr(unsafe.Pointer(&returned)))
	if status != 0 {
		return "", windows.NTStatus(status)
	}
	// TypeName is a UNICODE_STRING at offset 0: Length, MaximumLength, Buffer at 8.
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&buffer[0])), unsafe.Sizeof(buffer))
	length := uintptr(binary.LittleEndian.Uint16(raw[0:2]))
	address := uintptr(binary.LittleEndian.Uint64(raw[8:16]))
	base := uintptr(unsafe.Pointer(&buffer[0]))
	if length%2 != 0 || address < base || address-base > uintptr(len(raw)) || length > uintptr(len(raw))-(address-base) {
		return "", errors.New("malformed object type information")
	}
	offset := address - base
	name := make([]uint16, length/2)
	for i := range name {
		name[i] = binary.LittleEndian.Uint16(raw[offset+uintptr(2*i):])
	}
	return windows.UTF16ToString(name), nil
}

func registrarUsage() (uint32, uint64) {
	var count uint32
	getProcessHandleCount.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&count)))
	// PROCESS_MEMORY_COUNTERS_EX: PrivateUsage follows the ten base counters.
	type counters struct {
		Size, PageFaults                                                                                                          uint32
		PeakWorkingSet, WorkingSet, QuotaPeakPaged, QuotaPaged, QuotaPeakNonPaged, QuotaNonPaged, Pagefile, PeakPagefile, Private uintptr
	}
	m := counters{}
	m.Size = uint32(unsafe.Sizeof(m))
	if ok, _, _ := getProcessMemoryInfo.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&m)), uintptr(m.Size)); ok == 0 {
		return count, 0
	}
	return count, uint64(m.Private)
}
