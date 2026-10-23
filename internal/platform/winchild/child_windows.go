//go:build windows

// Package winchild starts the service's own image in an unnamed lifetime job.
// Creation and job assignment are one kernel operation; execution is separate.
package winchild

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/platform/winapi"
	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

const jobListAttribute = 0x0002000D

const forcedExitCode uint32 = 0xe04e5301

var closeOwner = func(owner winhandle.Owner, site string) error { return owner.HandleClose(site) }

// Hosted death injection immediately after creation, before identity checks.
// Production has no hook and never performs a later job-assignment operation.
var afterCreate func(windows.ProcessInformation)
var beforeTerminate func() // hosted natural-exit race barrier

var restrictHandles = func(attrs *windows.ProcThreadAttributeListContainer, handles []windows.Handle) error {
	return attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0]))
}

type Options struct {
	Args               []string
	Env                []string // explicit: the supervisor must choose the child's runtime limits
	Directory          string
	RegistrarBreakaway bool // explicit breakaway only; never SILENT_BREAKAWAY
}

type Identity struct {
	PID     uint32
	Created uint64 // Windows creation FILETIME, read through the pinned process handle
	Image   string
	File    FileID
}

type Exit struct {
	Code   uint32 // raw Windows exit, including exception codes
	Forced bool
}

type Process struct {
	Identity                         Identity
	Input, Output, Errors            *winhandle.File
	mu, closeMu, joinMu              sync.Mutex
	process, thread, job             winhandle.Owner
	done                             chan struct{}
	exit                             Exit
	waitErr, closeErr                error
	forced, resumed, closing, closed bool
	registrars                       []winhandle.Owner
	registrarsJoined                 bool
}

func environment(entries []string) ([]uint16, error) {
	if entries == nil {
		return nil, errors.New("child environment must be explicit")
	}
	var block []uint16
	for _, entry := range entries {
		key, _, found := strings.Cut(entry, "=")
		drive := len(entry) >= 4 && entry[0] == '=' && ((entry[1] >= 'A' && entry[1] <= 'Z') || (entry[1] >= 'a' && entry[1] <= 'z')) && entry[2:4] == ":="
		if !found || (key == "" && !drive) {
			return nil, errors.New("invalid child environment entry")
		}
		part, err := windows.UTF16FromString(entry)
		if err != nil {
			return nil, err
		}
		block = append(block, part...)
		if len(block) > 32766 {
			return nil, errors.New("child environment exceeds 32K characters")
		}
	}
	if len(block) == 0 {
		block = append(block, 0)
	}
	return append(block, 0), nil
}

func pipe() (*winhandle.File, *winhandle.File, error) {
	var read, write windows.Handle
	if err := windows.CreatePipe(&read, &write, nil, 0); err != nil {
		return nil, nil, err
	}
	return winhandle.NewFile(winhandle.Open(read, "guarded child pipe read"), "guarded-child-read"),
		winhandle.NewFile(winhandle.Open(write, "guarded child pipe write"), "guarded-child-write"), nil
}

func closeFile(f *winhandle.File) error {
	if f == nil {
		return nil
	}
	err := f.Close()
	if errors.Is(err, os.ErrClosed) {
		return nil
	}
	return err
}

// StartSelf returns a verified, still-suspended child. The caller must Resume
// or Close it. Only this process owns the job handle; it is never inherited.
// There is no arbitrary executable argument and no create-then-assign fallback.
func StartSelf(o Options) (_ *Process, err error) {
	if len(o.Args) == 0 || len(o.Args) > 128 || (o.Directory != "" && !filepath.IsAbs(o.Directory)) {
		return nil, errors.New("child needs a mode and an absolute working directory")
	}
	env, err := environment(o.Env)
	if err != nil {
		return nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if startupImageError != nil {
		return nil, fmt.Errorf("capture running image identity: %w", startupImageError)
	}
	app, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return nil, err
	}
	command, err := windows.UTF16FromString(windows.ComposeCommandLine(append([]string{exe}, o.Args...)))
	if err != nil || len(command) > 32767 {
		return nil, errors.New("invalid child command line")
	}
	var directory *uint16
	if o.Directory != "" {
		directory, err = windows.UTF16PtrFromString(o.Directory)
		if err != nil {
			return nil, err
		}
	}
	// Pin this path against replacement until creation and identity verification.
	image, err := windows.CreateFile(app, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("pin child image: %w", err)
	}
	imageOwner := winhandle.Open(image, "guarded child image pin")
	pinnedID, identityErr := fileID(image)
	if identityErr != nil || pinnedID != startupImageID {
		return nil, errors.Join(fmt.Errorf("running image file changed before child launch: %v", identityErr), closeOwner(imageOwner, "changed child image unpin"))
	}
	p := &Process{done: make(chan struct{})}
	var ends []*winhandle.File
	var inherited []winhandle.Owner
	created, transferred := false, false
	defer func() {
		err = errors.Join(err, closeOwner(imageOwner, "guarded child image unpin"))
		for _, h := range inherited {
			err = errors.Join(err, closeOwner(h, "guarded child inherited duplicate close"))
		}
		for _, f := range ends {
			err = errors.Join(err, closeFile(f))
		}
		if transferred && err == nil {
			return
		}
		if created {
			err = errors.Join(err, p.Close())
			return
		}
		if !p.job.IsZero() {
			err = errors.Join(err, closeOwner(p.job, "guarded child unused job close"))
		}
		err = errors.Join(err, closeFile(p.Input), closeFile(p.Output), closeFile(p.Errors))
	}()
	input, writer, err := pipe()
	if err != nil {
		return nil, err
	}
	p.Input, ends = writer, append(ends, input)
	reader, output, err := pipe()
	if err != nil {
		return nil, err
	}
	p.Output, ends = reader, append(ends, output)
	reader, stderr, err := pipe()
	if err != nil {
		return nil, err
	}
	p.Errors, ends = reader, append(ends, stderr)
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	p.job = winhandle.Open(job, "guarded child job")
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
		LimitFlags:         windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS | windows.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
		ActiveProcessLimit: 1,
	}}
	if o.RegistrarBreakaway {
		limits.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK
	}
	if err := winapi.SetJobInformation(job, windows.JobObjectExtendedLimitInformation, &limits); err != nil {
		return nil, err
	}
	var handles []windows.Handle
	for _, f := range ends {
		var h windows.Handle
		if err := windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(f.Fd()), windows.CurrentProcess(), &h, 0, true, windows.DUPLICATE_SAME_ACCESS); err != nil {
			return nil, err
		}
		inherited = append(inherited, winhandle.Open(h, "guarded child inherited pipe"))
		handles = append(handles, h)
	}
	attrs, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return nil, err
	}
	defer attrs.Delete()
	if err := restrictHandles(attrs, handles); err != nil {
		return nil, err
	}
	jobs := []windows.Handle{job}
	if err := attrs.Update(jobListAttribute, unsafe.Pointer(&jobs[0]), unsafe.Sizeof(jobs[0])); err != nil {
		return nil, err
	}
	si := windows.StartupInfoEx{StartupInfo: windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{})), Flags: windows.STARTF_USESTDHANDLES,
		StdInput: handles[0], StdOutput: handles[1], StdErr: handles[2]}, ProcThreadAttributeList: attrs.List()}
	var pi windows.ProcessInformation
	if err := windows.CreateProcess(app, &command[0], nil, nil, true,
		windows.CREATE_SUSPENDED|windows.DETACHED_PROCESS|windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_UNICODE_ENVIRONMENT,
		&env[0], directory, &si.StartupInfo, &pi); err != nil {
		return nil, fmt.Errorf("create contained child: %w", err)
	}
	p.process, p.thread = winhandle.Open(pi.Process, "guarded child process"), winhandle.Open(pi.Thread, "guarded child primary thread")
	created = true
	go p.observe()
	if afterCreate != nil {
		afterCreate(pi)
	}
	inJob, err := p.Contains(pi.Process)
	if err != nil || !inJob {
		return nil, fmt.Errorf("child was not atomically assigned to its job: %v", err)
	}
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(pi.Process, &creation, &exit, &kernel, &user); err != nil {
		return nil, err
	}
	path := make([]uint16, 32768)
	size := uint32(len(path))
	if err := windows.QueryFullProcessImageName(pi.Process, 0, &path[0], &size); err != nil {
		return nil, err
	}
	actual := windows.UTF16ToString(path[:size])
	actualID, err := imageIDAt(actual)
	if err != nil || actualID != startupImageID {
		return nil, fmt.Errorf("unexpected child image file identity at %q: %v", actual, err)
	}
	p.Identity = Identity{pi.ProcessId, uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime), actual, actualID}
	transferred = true
	return p, nil
}

// CheckRegistrarParent is called in the native child's private bootstrap.
// The registrar may break away only from our one-process, kill-on-close job.
// It still enters its OWN UI-restricted job atomically when it is created.
func CheckRegistrarParent() error {
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if err := winapi.QueryJobInformation(0, windows.JobObjectExtendedLimitInformation, &limits); err != nil {
		return fmt.Errorf("query supervisor child job: %w", err)
	}
	var ui windows.JOBOBJECT_BASIC_UI_RESTRICTIONS
	if err := winapi.QueryJobInformation(0, windows.JobObjectBasicUIRestrictions, &ui); err != nil {
		return err
	}
	return checkRegistrarLimits(limits.BasicLimitInformation, ui.UIRestrictionsClass)
}

func checkRegistrarLimits(limits windows.JOBOBJECT_BASIC_LIMIT_INFORMATION, ui uint32) error {
	flags := limits.LimitFlags
	required := uint32(windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK | windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS)
	if flags&required != required || flags&windows.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK != 0 || limits.ActiveProcessLimit != 1 || ui != 0 {
		return fmt.Errorf("unexpected supervisor child job: flags=%#x active_limit=%d ui=%#x", flags, limits.ActiveProcessLimit, ui)
	}
	return nil
}

var isProcessInJob = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")

// Contains inspects a caller-pinned process handle, never an unverified PID.
func (p *Process) Contains(process windows.Handle) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		return false, os.ErrClosed
	}
	address := isProcessInJob.Addr()
	var result uint32
	ok, _, err := syscall.SyscallN(address, uintptr(process), uintptr(p.job.Handle("guarded child membership")), uintptr(unsafe.Pointer(&result)))
	if ok == 0 {
		return false, err
	}
	return result != 0, nil
}

func (p *Process) Resume() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing || p.resumed {
		return errors.New("child already resumed or closing")
	}
	previous, err := windows.ResumeThread(p.thread.Handle("guarded child resume"))
	if err == nil && previous != 1 {
		err = fmt.Errorf("unexpected child suspend count %d", previous)
	}
	err = errors.Join(err, closeOwner(p.thread, "guarded child thread close"))
	p.thread = winhandle.Owner{}
	p.resumed = true
	return err
}

// Alive is a readiness snapshot through the pinned handle, never a PID lookup.
func (p *Process) Alive() (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		return false, os.ErrClosed
	}
	state, err := windows.WaitForSingleObject(p.process.Handle("guarded child readiness check"), 0)
	return err == nil && state == uint32(windows.WAIT_TIMEOUT), err
}

func (p *Process) observe() {
	_, err := windows.WaitForSingleObject(p.process.Handle("guarded child exit wait"), windows.INFINITE)
	var code uint32
	if err == nil {
		err = windows.GetExitCodeProcess(p.process.Handle("guarded child raw exit"), &code)
	}
	p.mu.Lock()
	p.exit, p.waitErr = Exit{code, p.forced && code == forcedExitCode}, err
	close(p.done)
	p.mu.Unlock()
}

func (p *Process) Wait(ctx context.Context) (Exit, error) {
	select {
	case <-ctx.Done():
		return Exit{}, ctx.Err()
	case <-p.done:
		if err := p.joinRegistrars(ctx); err != nil {
			return Exit{}, err
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.exit, p.waitErr
	}
}

func (p *Process) terminateLocked() error {
	select {
	case <-p.done:
		return nil
	default:
	}
	state, err := windows.WaitForSingleObject(p.process.Handle("guarded child pre-kill state"), 0)
	if err != nil || state == windows.WAIT_OBJECT_0 {
		return err
	}
	p.forced = true
	if beforeTerminate != nil {
		beforeTerminate()
	}
	return windows.TerminateJobObject(p.job.Handle("guarded child terminate"), forcedExitCode)
}

func (p *Process) Terminate() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		return os.ErrClosed
	}
	return p.terminateLocked()
}

// Close consumes every owner after exit. A timed-out join retains the process
// handle for a later retry; it never races a wait by closing that handle early.
func (p *Process) Close() error {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	if p.closed {
		return p.closeErr
	}
	p.mu.Lock()
	if !p.closing {
		p.closeErr = errors.Join(p.closeErr, p.terminateLocked(), closeOwner(p.job, "guarded child job close"))
		p.job = winhandle.Owner{}
		p.closing = true
	}
	p.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := p.Wait(ctx)
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(p.closeErr, err)
	}
	p.closeErr = errors.Join(p.closeErr, err)
	p.mu.Lock()
	if !p.thread.IsZero() {
		p.closeErr = errors.Join(p.closeErr, closeOwner(p.thread, "guarded child unresumed thread close"))
	}
	p.closeErr = errors.Join(p.closeErr, closeOwner(p.process, "guarded child process close"))
	for _, registrar := range p.registrars {
		p.closeErr = errors.Join(p.closeErr, closeOwner(registrar, "guarded registrar observer close"))
	}
	p.registrars = nil
	p.mu.Unlock()
	p.closeErr = errors.Join(p.closeErr, closeFile(p.Input), closeFile(p.Output), closeFile(p.Errors))
	p.closed = true
	return p.closeErr
}
