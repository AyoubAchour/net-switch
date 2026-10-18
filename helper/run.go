package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// runHidden starts a program with no console window, waits for it and
// returns its exit code. The startup task uses it to run the server: node.exe
// is a console program, so started directly by the Task Scheduler it opens a
// console window on the desktop. This helper is a windowless program itself.
//
// The helper and the program share a job object that ends them together, so
// the program never outlives the helper: when the Task Scheduler ends the
// task, or the helper is stopped, the server and its engine stop too.
func runHidden(program string, args []string) int {
	if !filepath.IsAbs(program) {
		fmt.Fprintf(os.Stderr, "run needs the full path of the program, not %q\n", program)
		return 2
	}
	if err := joinKillOnCloseJob(); err != nil {
		// Without the job the program still runs hidden; it just isn't
		// stopped together with this helper.
		fmt.Fprintf(os.Stderr, "can't tie the program to this helper: %v\n", err)
	}
	cmd := hiddenCommand(program, args)
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "can't start %s: %v\n", program, err)
		return 1
	}
	if err := cmd.Wait(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "lost track of %s: %v\n", program, err)
		return 1
	}
	return 0
}

// The program gets no console window, and its standard input and output go to
// the null device: nobody reads a background server's console.
func hiddenCommand(program string, args []string) *exec.Cmd {
	cmd := exec.Command(program, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	return cmd
}

// Puts this helper in a new job that Windows ends, with everything in it, when
// its last handle closes. The handle is never closed by hand, so that happens
// when this helper exits for any reason. A program started afterwards joins
// the job. Breaking away stays allowed, as it was before the helper started
// the server.
func joinKillOnCloseJob() error {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK,
		},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return err
	}
	if err := windows.AssignProcessToJobObject(job, windows.CurrentProcess()); err != nil {
		windows.CloseHandle(job)
		return err
	}
	return nil
}
