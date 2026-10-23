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
// that also opens and closes other handles cannot prove that a value it later
// closes, or that the driver closes, still names the object it opened. So the
// registration's device handle lives only in a registrar: a hidden mode of the
// same signed executable that opens the device once, registers rings in a
// shared section, and then only waits. It never closes, reuses or touches that
// value again; process teardown owns it, and the driver's handle-close cleanup
// then releases the rings.
//
// The registrar receives exactly five inherited handles through an explicit
// list: its control pipe (stdin), its reply pipe (stdout and stderr), the
// unnamed ring section and the two unnamed ring events. It is created in its
// own unnamed kill-on-close job atomically at CreateProcess (JOB_LIST), still
// suspended, then resumed. Only the engine holds that job handle, so an engine
// crash ends the job and the registrar with it, even if the crash happens
// before the registrar is resumed. No kernel object is named.

// RegistrarMode is the hidden argument for the registrar. Every program that
// starts sessions (the engine, TestISP and test binaries) dispatches it before
// anything else: if len(os.Args) == 2 && os.Args[1] == wintun.RegistrarMode,
// it calls os.Exit(wintun.RunRegistrar()).
const RegistrarMode = "__netswitch-wintun-registrar"

// procThreadAttributeJobList assigns the new process to a job at creation,
// before its first instruction, closing the create-then-assign orphan window.
const procThreadAttributeJobList = 0x0002000D

// Test seams. Production always uses its own executable, RegistrarMode, no
// extra environment and no before-resume hook; registrarClose consumes each
// owner through its real native close. Tests can inject a close-result error
// after consuming the owner to verify failure cleanup. registrarExecutable lets
// a test binary start the built netswitch-engine.exe as the registrar, so the
// measured helper is the production image rather than the test binary.
var (
	registrarExecutable   = os.Executable
	registrarCommand      = RegistrarMode
	registrarExtraEnv     []string
	registrarBeforeResume func(pid uint32, job windows.Handle)
	registrarStartTimeout = 15 * time.Second
	registrarClose        = func(o winhandle.Owner, site string) error { return o.HandleClose(site) }
)

var setRegistrarJobInformation = windows.NewLazySystemDLL("kernel32.dll").NewProc("SetInformationJobObject")

const (
	registrarVersion      = 1
	registrarReplyPrefix  = "WINTUN_REGISTRAR "
	registrarMessageLimit = 8 << 10
	registrarStopTimeout  = 2 * time.Second
	registrarKillTimeout  = 5 * time.Second
	wintunInterfacePrefix = `\\?\SWD#WINTUN#`
	memMapped             = 0x40000 // MEMORY_BASIC_INFORMATION.Type for a section view
)

var errRegistrarAlive = errors.New("Wintun registrar did not exit")

// errOwnerLost drives the removal path when the reader observes the registrar
// process exit. It wraps ErrDisconnected so maintain treats it as a lost
// session; the distinct ErrRegistrarExited reason is decided deterministically
// during teardown, never from a timed guess.
var errOwnerLost = fmt.Errorf("Wintun registration owner exited: %w", ErrDisconnected)

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
	PID               uint32 `json:"pid"`
	Ready             bool   `json:"ready"`
	Stage             string `json:"stage,omitempty"`
	Errno             uint32 `json:"errno,omitempty"`
	Error             string `json:"error,omitempty"`
	Address           uint64 `json:"address,omitempty"`
	MemoryType        uint32 `json:"memoryType,omitempty"`
	FootprintMeasured bool   `json:"footprintMeasured"`
	Handles           uint32 `json:"handles,omitempty"`
	PrivateBytes      uint64 `json:"privateBytes,omitempty"`
	HeapBytes         uint64 `json:"heapBytes,omitempty"`
	StackBytes        uint64 `json:"stackBytes,omitempty"`
}

// RegistrarStats describes the latest registrar of a session. FootprintMeasured
// is false when the registrar could not read its own process counters; the
// byte fields are then not a real measurement and must not be trusted.
type RegistrarStats struct {
	Starts            uint64 // registrars started by this session, including corruption recoveries
	PID               uint32
	StartNanos        uint64 // CreateProcess through the ready reply
	FootprintMeasured bool
	Handles           uint32
	PrivateBytes      uint64
	HeapBytes         uint64
	StackBytes        uint64
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

// alreadyExited polls the process without blocking. True means the registrar
// ended on its own, before we requested a stop.
func (g *registrar) alreadyExited() bool { return g.wait(0) }

func (g *registrar) exitCode() uint32 {
	var code uint32
	if windows.GetExitCodeProcess(g.process.Handle("Wintun registrar exit code"), &code) != nil {
		return ^uint32(0)
	}
	return code
}

// retire requests exit by closing the control pipe's only writer, then
// terminates the job if the registrar does not exit. It classifies the loss
// from the *completed* exit, not a pre-close sample: the registrar exited on
// its own (owner death) if it was already gone before our stop, or if it ended
// with a non-zero code without our escalation. A clean EOF stop exits zero, and
// our own escalation kill is engine-initiated, so neither counts as owner death.
// Both reasons are still an adapter-lost session; this only sets the diagnostic.
func (g *registrar) retire(closeHandle func(windows.Handle) error) (exited, lostBeforeStop bool, err error) {
	preStop := g.alreadyExited()
	err = g.control.Close("Wintun registrar control close", closeHandle)
	exited = g.wait(registrarStopTimeout)
	escalated := false
	if !exited {
		escalated = true
		err = errors.Join(err, windows.TerminateJobObject(g.job.Handle("Wintun registrar termination"), 1))
		exited = g.wait(registrarKillTimeout)
	}
	var code uint32 = ^uint32(0)
	if exited {
		code = g.exitCode()
	}
	lostBeforeStop = preStop || (exited && !escalated && code != 0)
	err = errors.Join(err, g.job.Close("Wintun registrar job close", closeHandle),
		g.process.Close("Wintun registrar process close", closeHandle))
	if !exited {
		err = errors.Join(err, errRegistrarAlive)
	}
	return exited, lostBeforeStop, err
}

func (g *registrar) end(r *rings, closeHandle func(windows.Handle) error) (bool, error) {
	started := winclock.Now()
	exited, lostBeforeStop, err := g.retire(closeHandle)
	r.ownerExitedFirst = lostBeforeStop
	r.closeProfile.DeviceNanos = uint64(winclock.Since(started))
	if exited {
		// Handle-table rundown precedes the process signal, so the driver's
		// cleanup has normally published both markers already. This is a logged
		// confirmation, not a precondition for freeing the engine's own view.
		started = winclock.Now()
		if !r.awaitRelease() {
			err = errors.Join(err, errRegistrationHeld)
		}
		r.closeProfile.DriverWaitNanos = uint64(winclock.Since(started))
	}
	// The engine never retains its view: the driver only ever locked the
	// registrar's separate reference, which is gone with the registrar process.
	return false, err
}

func (g *registrar) stats(starts uint64) RegistrarStats {
	return RegistrarStats{Starts: starts, PID: g.reply.PID, StartNanos: g.startNanos, FootprintMeasured: g.reply.FootprintMeasured,
		Handles: g.reply.Handles, PrivateBytes: g.reply.PrivateBytes, HeapBytes: g.reply.HeapBytes, StackBytes: g.reply.StackBytes}
}

// registrarEnvironment keeps the helper's runtime small and deterministic. It
// inherits nothing else from the engine's environment.
func registrarEnvironment() (*uint16, error) {
	entries := []string{"GOMAXPROCS=1", "GOGC=50", "GOMEMLIMIT=8MiB"}
	if root := os.Getenv("SystemRoot"); root != "" {
		entries = append(entries, "SystemRoot="+root)
	}
	entries = append(entries, registrarExtraEnv...)
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

type replyResult struct {
	output []byte
	err    error
}

func startRegistrar(path string, r *rings) (_ *registrar, err error) {
	if r.section.IsZero() || r.readOwner.IsZero() || r.writeOwner.IsZero() {
		return nil, errors.New("Wintun registrar requires a ring section and both ring events")
	}
	exe, err := registrarExecutable()
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
			err = errors.Join(err, registrarClose(owned[i], "Wintun registrar setup close"))
		}
		owned = nil
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, closeOwned())
		}
	}()
	remove := func(o winhandle.Owner) {
		for i := range owned {
			if owned[i] == o {
				owned = append(owned[:i], owned[i+1:]...)
				return
			}
		}
	}
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
	// Keep each pointer conversion at the annotated LazyProc.Call boundary.
	// x/sys's uintptr-taking SetInformationJobObject wrapper is not annotated;
	// new/KeepAlive alone would not prevent a stack move during lazy resolution.
	if ok, _, callErr := setRegistrarJobInformation.Call(uintptr(job.Handle("Wintun registrar job limits")), windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits)); ok == 0 {
		return nil, fmt.Errorf("limit Wintun registrar job: %w", callErr)
	}
	ui := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: windows.JOB_OBJECT_UILIMIT_DESKTOP |
		windows.JOB_OBJECT_UILIMIT_DISPLAYSETTINGS | windows.JOB_OBJECT_UILIMIT_EXITWINDOWS |
		windows.JOB_OBJECT_UILIMIT_GLOBALATOMS | windows.JOB_OBJECT_UILIMIT_HANDLES |
		windows.JOB_OBJECT_UILIMIT_READCLIPBOARD | windows.JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS |
		windows.JOB_OBJECT_UILIMIT_WRITECLIPBOARD}
	if ok, _, callErr := setRegistrarJobInformation.Call(uintptr(job.Handle("Wintun registrar UI limits")), windows.JobObjectBasicUIRestrictions,
		uintptr(unsafe.Pointer(&ui)), unsafe.Sizeof(ui)); ok == 0 {
		return nil, fmt.Errorf("limit Wintun registrar UI access: %w", callErr)
	}
	// Inheritable duplicates exist only until CreateProcess returns, and only
	// the explicit handle list below can pass them. Their open and close are
	// tracked so the generation tripwire catches any stale reuse.
	sources := []winhandle.Owner{controlRead, replyWrite, r.section, r.readOwner, r.writeOwner}
	var inheritedOwners []winhandle.Owner
	inherited := make([]windows.Handle, 0, len(sources))
	closeInherited := func() error {
		var e error
		for _, o := range inheritedOwners {
			e = errors.Join(e, registrarClose(o, "Wintun registrar inherited duplicate close"))
		}
		inheritedOwners = nil
		return e
	}
	defer func() {
		if len(inheritedOwners) != 0 {
			err = errors.Join(err, closeInherited())
		}
	}()
	for _, source := range sources {
		var dup windows.Handle
		if err = windows.DuplicateHandle(windows.CurrentProcess(), source.Handle("Wintun registrar inheritance source"),
			windows.CurrentProcess(), &dup, 0, true, windows.DUPLICATE_SAME_ACCESS); err != nil {
			return nil, err
		}
		inheritedOwners = append(inheritedOwners, winhandle.Open(dup, "Wintun registrar inherited duplicate"))
		inherited = append(inherited, dup)
	}
	config, err := json.Marshal(registrarConfig{Version: registrarVersion, Path: path, Capacity: r.send.capacity,
		ViewBytes: uint64(viewBytes(r.send.capacity)), Section: uint64(inherited[2]), Read: uint64(inherited[3]), Write: uint64(inherited[4])})
	if err != nil {
		return nil, err
	}
	attrs, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return nil, err
	}
	defer attrs.Delete()
	// Update retains each value pointer in attrs.pointers, so the inherited and
	// jobList backing arrays stay reachable (and, being heap, unmoved) until the
	// deferred attrs.Delete, which runs after CreateProcess has consumed them.
	if err = attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&inherited[0]), uintptr(len(inherited))*unsafe.Sizeof(inherited[0])); err != nil {
		return nil, err
	}
	jobList := []windows.Handle{job.Handle("Wintun registrar job list")}
	if err = attrs.Update(procThreadAttributeJobList, unsafe.Pointer(&jobList[0]), unsafe.Sizeof(jobList[0])); err != nil {
		return nil, fmt.Errorf("prepare Wintun registrar job membership: %w", err)
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
	// Created suspended and already in the kill-on-close job: DETACHED_PROCESS
	// because the registrar needs no console; its I/O is the two pipes.
	flags := uint32(windows.CREATE_SUSPENDED | windows.DETACHED_PROCESS | windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_UNICODE_ENVIRONMENT)
	if supervisedRegistrar.Load() {
		flags |= windows.CREATE_BREAKAWAY_FROM_JOB
	}
	if err = windows.CreateProcess(app, commandLine, nil, nil, true,
		flags,
		environment, nil, &si.StartupInfo, &pi); err != nil {
		return nil, fmt.Errorf("start Wintun registrar: %w", err)
	}
	process := winhandle.Open(pi.Process, "Wintun registrar process open")
	thread := winhandle.Open(pi.Thread, "Wintun registrar thread open")
	g := &registrar{process: process, job: job, control: controlWrite}
	// From here a failure must end the suspended or running registrar before any
	// of its handles close: it may already hold a registration. The process is
	// already in the job, so terminating either reaches it.
	abandon := func(cause error) error {
		windows.TerminateJobObject(job.Handle("Wintun registrar setup termination"), 1)
		windows.TerminateProcess(process.Handle("Wintun registrar setup process termination"), 1)
		var err error
		if !g.wait(registrarKillTimeout) {
			err = errRegistrarAlive
		}
		return errors.Join(cause, err, registrarClose(process, "Wintun registrar setup process close"))
	}
	if err = closeInherited(); err != nil {
		return nil, abandon(errors.Join(err, registrarClose(thread, "Wintun registrar thread close")))
	}
	// Close the parent's own ends of the child's pipes so the child holds the
	// only control-read and reply-write ends. Its exit then ends the reply read.
	// A close consumes its owner even on failure, so drop each from cleanup
	// responsibility regardless of result; never close a consumed owner twice.
	controlReadErr := registrarClose(controlRead, "Wintun registrar control read close")
	remove(controlRead)
	replyWriteErr := registrarClose(replyWrite, "Wintun registrar reply write close")
	remove(replyWrite)
	if err = errors.Join(controlReadErr, replyWriteErr); err != nil {
		return nil, abandon(errors.Join(err, registrarClose(thread, "Wintun registrar thread close")))
	}
	if registrarBeforeResume != nil {
		registrarBeforeResume(pi.ProcessId, job.Handle("Wintun registrar before-resume witness"))
	}
	_, resumeErr := windows.ResumeThread(thread.Handle("Wintun registrar resume"))
	if err = errors.Join(resumeErr, registrarClose(thread, "Wintun registrar thread close")); err != nil {
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
	// The reply goroutine owns replyRead for its whole lifetime and closes it,
	// so no close can race an in-flight ReadFile.
	remove(replyRead)
	replyDone := make(chan replyResult, 1)
	go func() {
		output, rerr := readLine(replyRead.Handle("Wintun registrar reply"), registrarMessageLimit)
		replyDone <- replyResult{output, errors.Join(rerr, registrarClose(replyRead, "Wintun registrar reply read close"))}
	}()
	timer := time.NewTimer(registrarStartTimeout)
	var reply replyResult
	select {
	case reply = <-replyDone:
		timer.Stop()
	case <-timer.C:
		cause := abandon(fmt.Errorf("Wintun registrar did not report within %v", registrarStartTimeout))
		select { // the killed child closes its write end, ending readLine promptly
		case reply = <-replyDone:
			_, replyErr := parseReply(reply.output, reply.err)
			cause = errors.Join(cause, replyErr)
		case <-time.After(registrarKillTimeout):
			cause = errors.Join(cause, errors.New("Wintun registrar reply reader did not finish after termination"))
		}
		return nil, cause
	}
	g.reply, err = parseReply(reply.output, reply.err)
	if err == nil && g.reply.PID != pi.ProcessId {
		err = fmt.Errorf("Wintun registrar reported process %d, started %d", g.reply.PID, pi.ProcessId)
	}
	if err != nil {
		cause := err
		if g.wait(registrarStopTimeout) {
			cause = fmt.Errorf("%w (registrar exit code %#x)", err, g.exitCode())
		}
		return nil, abandon(cause)
	}
	g.startNanos = uint64(winclock.Since(started))
	owned = nil // controlWrite and job are now owned by g
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

func parseReply(output []byte, readErr error) (reply registrarReply, err error) {
	// A valid ready message does not excuse a failed read-owner close. Preserve
	// the underlying read/close error on malformed and failure replies too.
	defer func() { err = errors.Join(err, readErr) }()
	text := string(output)
	if !strings.HasPrefix(text, registrarReplyPrefix) {
		return reply, fmt.Errorf("Wintun registrar gave no reply: %q", text)
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
func RunRegistrar() int { return runRegistrar(registerDevice) }

// registerDevice opens the device once and registers the rings. It has no close
// path: process teardown closes the handle, and the driver may close it earlier
// during removal. The value is never used again after this call.
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

// registrarStdHandles requires both standard handles to be the engine's pipes.
func registrarStdHandles() (stdin, stdout windows.Handle, err error) {
	if stdin, err = windows.GetStdHandle(windows.STD_INPUT_HANDLE); err != nil {
		return 0, 0, err
	}
	if stdout, err = windows.GetStdHandle(windows.STD_OUTPUT_HANDLE); err != nil {
		return 0, 0, err
	}
	if !isPipe(stdin) || !isPipe(stdout) {
		return 0, 0, errors.New("internal Wintun registrar mode requires the engine's inherited pipes")
	}
	return stdin, stdout, nil
}

func sendRegistrarReply(stdout windows.Handle, reply registrarReply) {
	encoded, _ := json.Marshal(reply)
	message := append([]byte(registrarReplyPrefix), encoded...)
	message = append(message, '\n')
	var written uint32
	windows.WriteFile(stdout, message, &written, nil)
}

// prepareRegistration validates the configuration and inherited handles and
// maps the ring section. Both the production registrar and the test fixtures
// use it, so validation has a single source.
func prepareRegistration(config registrarConfig) (view uintptr, desc registration, memoryType uint32, stage string, err error) {
	if config.Version != registrarVersion || !validCapacity(config.Capacity) || config.ViewBytes != uint64(viewBytes(config.Capacity)) {
		return 0, desc, 0, "configuration", errors.New("unsupported registrar configuration")
	}
	if !strings.HasPrefix(strings.ToUpper(config.Path), wintunInterfacePrefix) || strings.ContainsRune(config.Path, 0) {
		return 0, desc, 0, "configuration", errors.New("not a Wintun device interface path")
	}
	section, read, write := windows.Handle(config.Section), windows.Handle(config.Read), windows.Handle(config.Write)
	if section == read || section == write || read == write {
		return 0, desc, 0, "inheritance", errors.New("registrar handles are not distinct")
	}
	for _, want := range []struct {
		h    windows.Handle
		kind string
	}{{section, "Section"}, {read, "Event"}, {write, "Event"}} {
		kind, err := objectType(want.h)
		if err != nil {
			return 0, desc, 0, "inheritance", fmt.Errorf("inherited handle %#x: %w", want.h, err)
		}
		if kind != want.kind {
			return 0, desc, 0, "inheritance", fmt.Errorf("inherited handle %#x is %q, not %q", want.h, kind, want.kind)
		}
	}
	size := uintptr(config.ViewBytes)
	view, err = windows.MapViewOfFile(section, windows.FILE_MAP_READ|windows.FILE_MAP_WRITE, 0, 0, size)
	if err != nil {
		return 0, desc, 0, "map", err
	}
	var memory windows.MemoryBasicInformation
	if err := windows.VirtualQuery(view, &memory, unsafe.Sizeof(memory)); err != nil {
		return view, desc, 0, "map", err
	}
	if memory.Type != memMapped || memory.RegionSize < size {
		return view, desc, memory.Type, "map", fmt.Errorf("inherited section view type %#x, %d bytes", memory.Type, memory.RegionSize)
	}
	data := mappedSlice(view, int(size))
	rb := ringBytes(config.Capacity)
	desc = registration{
		Send:    ringRegistration{uint32(rb), &data[0], read},
		Receive: ringRegistration{uint32(rb), &data[rb], write},
	}
	return view, desc, memory.Type, "", nil
}

// registrarWaitForStop blocks until the control pipe reaches EOF: the engine's
// stop request, or its exit.
func registrarWaitForStop(stdin windows.Handle) int {
	var chunk [64]byte
	for {
		var n uint32
		if err := windows.ReadFile(stdin, chunk[:], &n, nil); err != nil || n == 0 {
			return 0
		}
	}
}

func runRegistrar(register func(string, *registration) error) int {
	stdin, stdout, err := registrarStdHandles()
	if err != nil {
		fmt.Fprintln(os.Stderr, "netswitch: "+err.Error())
		return 2
	}
	fail := func(stage string, err error) int {
		reply := registrarReply{PID: windows.GetCurrentProcessId(), Stage: stage, Error: err.Error()}
		var errno windows.Errno
		if errors.As(err, &errno) {
			reply.Errno = uint32(errno)
		}
		sendRegistrarReply(stdout, reply)
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
	view, desc, memoryType, stage, err := prepareRegistration(config)
	if err != nil {
		return fail(stage, err)
	}
	if err := register(config.Path, &desc); err != nil {
		return fail("register", err)
	}
	handles, private, measured := registrarUsage()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	sendRegistrarReply(stdout, registrarReply{PID: windows.GetCurrentProcessId(), Ready: true, Address: uint64(view), MemoryType: memoryType,
		FootprintMeasured: measured, Handles: handles, PrivateBytes: private, HeapBytes: stats.HeapAlloc, StackBytes: stats.StackInuse})
	return registrarWaitForStop(stdin)
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

// registrarUsage returns the handle count, private bytes, and whether both
// measurements succeeded. A failed query is reported as unmeasured, never as a
// fabricated zero footprint.
func registrarUsage() (uint32, uint64, bool) {
	var count uint32
	ok1, _, _ := getProcessHandleCount.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&count)))
	// PROCESS_MEMORY_COUNTERS_EX: PrivateUsage follows the ten base counters.
	type counters struct {
		Size, PageFaults                                                                                                          uint32
		PeakWorkingSet, WorkingSet, QuotaPeakPaged, QuotaPaged, QuotaPeakNonPaged, QuotaNonPaged, Pagefile, PeakPagefile, Private uintptr
	}
	m := counters{}
	m.Size = uint32(unsafe.Sizeof(m))
	ok2, _, _ := getProcessMemoryInfo.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&m)), uintptr(m.Size))
	return count, uint64(m.Private), ok1 != 0 && ok2 != 0
}
