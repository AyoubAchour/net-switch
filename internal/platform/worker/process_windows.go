package worker

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type process struct {
	handle, job   windows.Handle
	output, input *os.File
	errors        *os.File
	wait          sync.Once
	waitErr       error
	close         sync.Once
}

func (p *process) Input() io.WriteCloser { return p.input }
func (p *process) Output() io.ReadCloser { return p.output }
func (p *process) Errors() io.ReadCloser { return p.errors }
func (p *process) Kill() error           { return windows.TerminateJobObject(p.job, 1) }
func (p *process) Wait() error {
	p.wait.Do(func() {
		_, p.waitErr = windows.WaitForSingleObject(p.handle, windows.INFINITE)
		if p.waitErr == nil {
			var code uint32
			p.waitErr = windows.GetExitCodeProcess(p.handle, &code)
			if code != 0 {
				p.waitErr = fmt.Errorf("worker exited %d (0x%08X)", code, code)
				if code == 0xc0000142 {
					p.waitErr = fmt.Errorf("%w: STATUS_DLL_INIT_FAILED during Windows process initialization", p.waitErr)
				}
			}
		}
	})
	return p.waitErr
}
func (p *process) Close() error {
	p.close.Do(func() {
		_ = p.Kill()
		_ = p.Wait()
		p.input.Close()
		p.output.Close()
		p.errors.Close()
		windows.CloseHandle(p.handle)
		windows.CloseHandle(p.job)
	})
	return nil
}

const workerUILimits = windows.JOB_OBJECT_UILIMIT_DESKTOP | windows.JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
	windows.JOB_OBJECT_UILIMIT_EXITWINDOWS | windows.JOB_OBJECT_UILIMIT_GLOBALATOMS |
	windows.JOB_OBJECT_UILIMIT_HANDLES | windows.JOB_OBJECT_UILIMIT_READCLIPBOARD |
	windows.JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS | windows.JOB_OBJECT_UILIMIT_WRITECLIPBOARD

// Reads use a Medium-integrity token with Administrators deny-only. Writes and
// outside (which enables TCP counters) retain admin access with privileges
// stripped. Both enter a bounded worker-only job before they can execute.
func Start(executable string, args []string) (Process, error) {
	// No worker needs a console. CREATE_NO_WINDOW still enters hidden-console
	// initialization for console-subsystem binaries, which fails with a lowered
	// token on hosted Windows (0xC0000142). DETACHED_PROCESS avoids that path;
	// the only inherited I/O remains our three explicit pipes. GUI-subsystem
	// builds and USER32/GDI icon extraction work with the same token/job limits.
	return start(executable, args, nil, windows.DETACHED_PROCESS, workerUILimits)
}

// The explicit startup inputs let hosted tests distinguish loader, desktop and
// job failures. Production callers always go through Start's fixed policy.
func start(executable string, args []string, desktop *uint16, creationFlags, uiLimits uint32) (Process, error) {
	if !filepath.IsAbs(executable) || len(args) < 2 || args[0] != "worker" {
		return nil, fmt.Errorf("worker launcher requires its absolute executable and a worker mode")
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			windows.CloseHandle(job)
		}
	}()
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags:         windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS | windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY,
			ActiveProcessLimit: 1,
		},
		ProcessMemoryLimit: 256 * 1024 * 1024,
	}
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return nil, err
	}
	ui := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: uiLimits}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectBasicUIRestrictions, uintptr(unsafe.Pointer(&ui)), uint32(unsafe.Sizeof(ui))); err != nil {
		return nil, fmt.Errorf("limit worker UI access: %w", err)
	}
	var token windows.Token
	if err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT, &token); err != nil {
		return nil, err
	}
	defer token.Close()
	restricted, err := workerToken(token, adminWorker(args))
	if err != nil {
		return nil, err
	}
	defer restricted.Close()
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer writer.Close()
	defer func() {
		if !ok {
			reader.Close()
		}
	}()
	stdin, hold, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer stdin.Close()
	defer func() {
		if !ok {
			hold.Close()
		}
	}()
	errorReader, errorWriter, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer errorWriter.Close()
	defer func() {
		if !ok {
			errorReader.Close()
		}
	}()
	// stderr has its own pipe, including when Control has no console. Duplicate only these three
	// handles and use an explicit inheritance list, so jobs/tokens never leak.
	source := []windows.Handle{windows.Handle(stdin.Fd()), windows.Handle(writer.Fd()), windows.Handle(errorWriter.Fd())}
	handles := make([]windows.Handle, 3)
	for i, h := range source {
		if err := windows.DuplicateHandle(windows.CurrentProcess(), h, windows.CurrentProcess(), &handles[i], 0, true, windows.DUPLICATE_SAME_ACCESS); err != nil {
			for _, h := range handles {
				if h != 0 {
					windows.CloseHandle(h)
				}
			}
			return nil, err
		}
	}
	defer func() {
		for _, h := range handles {
			windows.CloseHandle(h)
		}
	}()
	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return nil, err
	}
	defer attrs.Delete()
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		return nil, err
	}
	si := windows.StartupInfoEx{StartupInfo: windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{})), Flags: windows.STARTF_USESTDHANDLES, StdInput: handles[0], StdOutput: handles[1], StdErr: handles[2]}, ProcThreadAttributeList: attrs.List()}
	si.Desktop = desktop
	quoted := []string{windows.EscapeArg(executable)}
	for _, a := range args {
		quoted = append(quoted, windows.EscapeArg(a))
	}
	app, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return nil, err
	}
	cmd, err := windows.UTF16PtrFromString(strings.Join(quoted, " "))
	if err != nil {
		return nil, err
	}
	var pi windows.ProcessInformation
	if err = windows.CreateProcessAsUser(restricted, app, cmd, nil, nil, true, windows.CREATE_SUSPENDED|creationFlags|windows.EXTENDED_STARTUPINFO_PRESENT, nil, nil, &si.StartupInfo, &pi); err != nil {
		return nil, err
	}
	defer windows.CloseHandle(pi.Thread)
	if err = windows.AssignProcessToJobObject(job, pi.Process); err != nil {
		windows.TerminateProcess(pi.Process, 1)
		windows.CloseHandle(pi.Process)
		return nil, err
	}
	if _, err = windows.ResumeThread(pi.Thread); err != nil {
		windows.TerminateJobObject(job, 1)
		windows.CloseHandle(pi.Process)
		return nil, err
	}
	ok = true
	return &process{handle: pi.Process, job: job, output: reader, input: hold, errors: errorReader}, nil
}

func workerToken(token windows.Token, administrative bool) (windows.Token, error) {
	var disabled []windows.SIDAndAttributes
	if !administrative {
		groups, err := token.GetTokenGroups()
		if err != nil {
			return 0, err
		}
		for _, group := range groups.AllGroups() {
			text := group.Sid.String()
			if text == "" {
				return 0, fmt.Errorf("could not read a worker token group SID")
			}
			if elevatedGroupText(text) {
				disabled = append(disabled, windows.SIDAndAttributes{Sid: group.Sid})
			}
		}
	}
	var disabledSIDs *windows.SIDAndAttributes
	if len(disabled) != 0 {
		disabledSIDs = &disabled[0]
	}
	var restricted windows.Token
	proc := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")
	result, _, callErr := proc.Call(uintptr(token), 1, uintptr(len(disabled)), uintptr(unsafe.Pointer(disabledSIDs)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&restricted)))
	if result == 0 {
		return 0, fmt.Errorf("restrict worker token: %w", callErr)
	}
	if !administrative {
		if err := mediumIntegrity(restricted); err != nil {
			restricted.Close()
			return 0, err
		}
	}
	return restricted, nil
}

func mediumIntegrity(token windows.Token) error {
	medium, err := windows.CreateWellKnownSid(windows.WinMediumLabelSid)
	if err != nil {
		return err
	}
	label := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: medium, Attributes: windows.SE_GROUP_INTEGRITY}}
	if err := windows.SetTokenInformation(token, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&label)), label.Size()); err != nil {
		return fmt.Errorf("lower worker integrity: %w", err)
	}
	return nil
}

// UAC's elevated group set, from Microsoft's "Teach Your Apps To Work With
// Windows Vista User Account Control", Figure 3. Match the full SID namespace:
// a foreign-domain privileged group is just as powerful as the local domain's,
// while an unrelated SID with the same final RID must remain untouched.
func elevatedGroup(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	return elevatedGroupText(sid.String())
}

func elevatedGroupText(text string) bool {
	// The x/sys pointer-returning SID helpers round-trip Go-backed SID
	// addresses through uintptr, which fails checkptr. Canonical SID text
	// copies the value instead and keeps the exact authority/count checks.
	parts := strings.Split(text, "-")
	if len(parts) < 5 || parts[0] != "S" || parts[1] != "1" || parts[2] != "5" {
		return false
	}
	if len(parts) == 5 && parts[3] == "32" {
		switch parts[4] {
		case "544", "547", "548", "549", "550", "551", "554", "556":
			return true
		}
	}
	if len(parts) == 8 && parts[3] == "21" {
		switch parts[7] {
		case "512", "516", "517", "518", "519", "520", "553":
			return true
		}
	}
	return false
}

func adminWorker(args []string) bool {
	mode := args[1]
	if mode == "query" && len(args) > 2 {
		mode = args[2]
	}
	switch mode {
	case "outside", "policy-set", "metrics-set", "metrics-restore", "protect-directory",
		"stop-process", "close-tcp", "autostart-set", "autostart-upgrade":
		return true
	}
	return false
}
