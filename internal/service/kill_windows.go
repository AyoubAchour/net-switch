package service

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// ForceStop pins and verifies the SCM process before terminating it. Closing
// its guarded child job releases TUN handles; SCM recovery owns journal cleanup.
func ForceStop(ctx context.Context, name string) error {
	s, err := open(name, windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return err
	}
	defer s.Close()
	state, err := s.Query()
	if err != nil {
		return err
	}
	if state.State == svc.Stopped {
		return nil
	}
	if state.ProcessId == 0 {
		return errors.New("service has no terminable process")
	}
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, state.ProcessId)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	config, err := s.Config()
	if err != nil {
		return err
	}
	args, err := windows.DecomposeCommandLine(config.BinaryPathName)
	if err != nil || len(args) == 0 {
		return errors.New("invalid service image configuration")
	}
	image := make([]uint16, 32768)
	size := uint32(len(image))
	if err := windows.QueryFullProcessImageName(h, 0, &image[0], &size); err != nil {
		return err
	}
	current, err := s.Query()
	if err != nil {
		return err
	}
	if current.ProcessId != state.ProcessId || !strings.EqualFold(filepath.Clean(args[0]), filepath.Clean(windows.UTF16ToString(image[:size]))) {
		return errors.New("service process identity changed before forced stop")
	}
	if err := windows.TerminateProcess(h, 1); err != nil {
		return err
	}
	return WaitStopped(ctx, name)
}
