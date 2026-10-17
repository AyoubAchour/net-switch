package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

func creationTime(process windows.Handle) (uint64, error) {
	var created, exited, kernel, user windows.Filetime
	err := windows.GetProcessTimes(process, &created, &exited, &kernel, &user)
	return uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime), err
}

func guardMatches(actual, expected string, parentCreated, childCreated uint64) bool {
	return actual != "" && strings.EqualFold(actual, expected) && childCreated > parentCreated
}

// Hold both process handles from startup through termination. A reused PID
// can never change the process these handles refer to.
func guard(opts options) error {
	parent, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, opts.parent)
	if err != nil {
		return fmt.Errorf("guard can't open parent: %w", err)
	}
	defer windows.CloseHandle(parent)
	child, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE, false, uint32(opts.child))
	if err != nil {
		return fmt.Errorf("guard can't open child: %w", err)
	}
	defer windows.CloseHandle(child)
	parentCreated, err := creationTime(parent)
	if err != nil {
		return err
	}
	childCreated, err := creationTime(child)
	if err != nil {
		return err
	}
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(child, 0, &buffer[0], &size); err != nil {
		return err
	}
	actualPath := windows.UTF16ToString(buffer[:size])
	if !guardMatches(actualPath, opts.childPath, parentCreated, childCreated) {
		return fmt.Errorf("guard refused child: image %q (expected %q), created %d (parent %d)", actualPath, opts.childPath, childCreated, parentCreated)
	}
	// The acknowledgment lets Node distinguish an armed guard from one that
	// couldn't open the handles. stdin intentionally does not control this mode.
	if err := writeLine(map[string]bool{"ready": true}); err != nil {
		return err
	}
	result, err := windows.WaitForMultipleObjects([]windows.Handle{parent, child}, false, windows.INFINITE)
	if err != nil {
		return err
	}
	if result != windows.WAIT_OBJECT_0 {
		return nil
	}
	state, err := windows.WaitForSingleObject(child, 0)
	if err != nil || state != uint32(windows.WAIT_TIMEOUT) {
		return err
	}
	return windows.TerminateProcess(child, 1)
}
