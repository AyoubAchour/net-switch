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
				p.waitErr = fmt.Errorf("worker exited %d", code)
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

// Reads use a Medium-integrity token with Administrators deny-only. Writes and
// outside (which enables TCP counters) retain admin access with privileges
// stripped. Both enter a bounded worker-only job before they can execute.
func Start(executable string, args []string) (Process, error) {
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
	ui := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: windows.JOB_OBJECT_UILIMIT_DESKTOP | windows.JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
		windows.JOB_OBJECT_UILIMIT_EXITWINDOWS | windows.JOB_OBJECT_UILIMIT_GLOBALATOMS |
		windows.JOB_OBJECT_UILIMIT_HANDLES | windows.JOB_OBJECT_UILIMIT_READCLIPBOARD |
		windows.JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS | windows.JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectBasicUIRestrictions, uintptr(unsafe.Pointer(&ui)), uint32(unsafe.Sizeof(ui))); err != nil {
		return nil, fmt.Errorf("limit worker UI access: %w", err)
	}
	var token windows.Token
	if err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT, &token); err != nil {
		return nil, err
	}
	defer token.Close()
	var restricted windows.Token
	var disabled windows.SIDAndAttributes
	var count uintptr
	var disabledSIDs *windows.SIDAndAttributes
	if !adminWorker(args) {
		admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
		if err != nil {
			return nil, err
		}
		disabled.Sid = admin
		count, disabledSIDs = 1, &disabled
	}
	proc := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")
	result, _, callErr := proc.Call(uintptr(token), 1, count, uintptr(unsafe.Pointer(disabledSIDs)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&restricted)))
	if result == 0 {
		return nil, fmt.Errorf("restrict worker token: %w", callErr)
	}
	defer restricted.Close()
	if !adminWorker(args) {
		medium, err := windows.CreateWellKnownSid(windows.WinMediumLabelSid)
		if err != nil {
			return nil, err
		}
		label := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: medium, Attributes: windows.SE_GROUP_INTEGRITY}}
		if err := windows.SetTokenInformation(restricted, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&label)), label.Size()); err != nil {
			return nil, fmt.Errorf("lower worker integrity: %w", err)
		}
	}
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
	if err = windows.CreateProcessAsUser(restricted, app, cmd, nil, nil, true, windows.CREATE_SUSPENDED|windows.CREATE_NO_WINDOW|windows.EXTENDED_STARTUPINFO_PRESENT, nil, nil, &si.StartupInfo, &pi); err != nil {
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
