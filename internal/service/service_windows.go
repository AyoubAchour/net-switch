package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

type handler struct {
	run Program
	err error
}

func ReportError(name string, err error) {
	log, openErr := eventlog.Open(name)
	if openErr == nil {
		defer log.Close()
		_ = log.Error(1, err.Error())
	}
	fmt.Fprintln(os.Stderr, name+":", err)
}

func (h *handler) Execute(_ []string, requests <-chan svc.ChangeRequest, updates chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	ctx, events := eventContext(ctx)
	status := svc.Status{State: svc.StartPending, WaitHint: 30000}
	updates <- status
	ready := make(chan struct{})
	result := make(chan error, 1)
	var once sync.Once
	go func() { result <- h.run(ctx, func() { once.Do(func() { close(ready) }) }) }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ready:
			ready = nil
			status = svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPowerEvent | svc.AcceptSessionChange}
			updates <- status
		case request := <-requests:
			switch request.Cmd {
			case svc.Stop, svc.Shutdown:
				status = svc.Status{State: svc.StopPending, WaitHint: 30000}
				updates <- status
				cancel(nil)
			case svc.Cmd(128):
				status = svc.Status{State: svc.StopPending, WaitHint: 30000}
				updates <- status
				cancel(ErrRestart)
			case svc.PowerEvent:
				if request.EventType == 18 {
					events <- Event{Resume: true}
				} // PBT_APMRESUMEAUTOMATIC
			case svc.SessionChange:
				if request.EventType == 6 && request.EventData != 0 { // WTS_SESSION_LOGOFF
					var data struct{ Size, Session uint32 }
					var read uintptr
					// svc exposes the callback buffer as uintptr. Copy it
					// through the OS instead of manufacturing a Go pointer.
					if err := windows.ReadProcessMemory(windows.CurrentProcess(), request.EventData, (*byte)(unsafe.Pointer(&data)), unsafe.Sizeof(data), &read); err == nil && read == unsafe.Sizeof(data) && data.Size >= uint32(read) {
						events <- Event{Logoff: true, Session: data.Session}
					} else {
						fmt.Fprintln(os.Stderr, "session-change data unavailable; checking all owner sessions")
						events <- Event{Logoff: true, Session: ^uint32(0)}
					}
				}
			case svc.Interrogate:
				updates <- status
			}
		case <-ticker.C:
			if status.State == svc.StartPending || status.State == svc.StopPending {
				status.CheckPoint++
				updates <- status
			}
		case h.err = <-result:
			if h.err != nil {
				return true, 1
			}
			return false, 0
		}
	}
}
func RequestRestart(ctx context.Context, name string) error {
	s, err := open(name, windows.SERVICE_USER_DEFINED_CONTROL)
	if err != nil {
		return err
	}
	defer s.Close()
	_, err = s.Control(svc.Cmd(128))
	return err
}
func Run(name string, program Program) error {
	ok, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("service mode must be started by the Windows service manager")
	}
	h := &handler{run: program}
	if err := svc.Run(name, h); err != nil {
		return err
	}
	return h.err
}
func open(name string, rights uint32) (*mgr.Service, error) {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil, err
	}
	defer windows.CloseServiceHandle(m)
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	h, err := windows.OpenService(m, n, rights)
	if err != nil {
		return nil, err
	}
	return &mgr.Service{Name: name, Handle: h}, nil
}
func Query(name string) (Status, error) {
	s, err := open(name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return Status{}, err
	}
	defer s.Close()
	state, err := s.Query()
	return Status{PID: state.ProcessId, Running: state.State == svc.Running, Stopped: state.State == svc.Stopped}, err
}
func Start(ctx context.Context, name string) error {
	s, err := open(name, windows.SERVICE_START|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer s.Close()
	for {
		state, err := s.Query()
		if err != nil {
			return err
		}
		if state.State != svc.StopPending {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	err = s.Start()
	if err != nil && err != windows.ERROR_SERVICE_ALREADY_RUNNING {
		return err
	}
	for {
		state, err := s.Query()
		if err != nil {
			return err
		}
		if state.State == svc.Running {
			return nil
		}
		if state.State == svc.Stopped {
			return fmt.Errorf("%s stopped during startup (exit %d)", name, state.Win32ExitCode)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}
func Activate(ctx context.Context) error { return Start(ctx, Control) }
func Stop(ctx context.Context, name string) error {
	s, err := open(name, windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer s.Close()
	_, err = s.Control(svc.Stop)
	if err != nil && err != windows.ERROR_SERVICE_NOT_ACTIVE {
		return err
	}
	for {
		state, err := s.Query()
		if err != nil {
			return err
		}
		if state.State == svc.Stopped {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}
func SetOwner(owner string) error {
	if owner != "" {
		if _, err := windows.StringToSid(owner); err != nil {
			return err
		}
	}
	s, err := open(Control, windows.WRITE_DAC)
	if err != nil {
		return err
	}
	defer s.Close()
	dacl := "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;LC;;;AU)"
	if owner != "" {
		dacl += "(A;;LCRPLO;;;" + owner + ")"
	}
	return setDACL(s.Handle, dacl)
}
func setDACL(handle windows.Handle, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(handle, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
func Install(c Config) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	for _, entry := range []struct{ name, file string }{{Engine, "netswitch-engine.exe"}, {Control, "netswitch.exe"}} {
		path := filepath.Join(c.Directory, entry.file)
		if _, err := os.Stat(path); err != nil {
			return err
		}
		s, err := m.CreateService(entry.name, path, mgr.Config{StartType: mgr.StartManual, ErrorControl: mgr.ErrorNormal, DisplayName: entry.name, Description: "Net Switch routing service", ServiceStartName: "LocalSystem"}, "service", "--data", c.Data)
		if err == windows.ERROR_SERVICE_EXISTS {
			return fmt.Errorf("%s already installed; use the migration/update transaction to replace it", entry.name)
		}
		if err != nil {
			return err
		}
		if entry.name == Engine {
			// Administrators retain configuration/deletion for the installer,
			// but only SYSTEM receives start/stop rights.
			err = setDACL(s.Handle, "D:P(A;;GA;;;SY)(A;;0xF0007;;;BA)(A;;LC;;;AU)")
			if err == nil {
				err = s.SetRecoveryCommand(windows.ComposeCommandLine([]string{filepath.Join(c.Directory, "netswitchctl.exe"), "recover", "--engine", "--data", c.Data}))
			}
			if err == nil {
				err = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.RunCommand, Delay: 0}}, 600)
			}
		} else {
			err = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: time.Second}, {Type: mgr.ServiceRestart, Delay: 2 * time.Second}, {Type: mgr.ServiceRestart, Delay: 5 * time.Second}}, 600)
		}
		if err == nil {
			err = s.SetRecoveryActionsOnNonCrashFailures(true)
		}
		if err == nil {
			// Keep the small set required by worker token creation and native
			// reads. Only Engine can load the signed TUN driver.
			// MULTI_SZ needs embedded zeroes; build it explicitly.
			var names []uint16
			privileges := []string{"SeChangeNotifyPrivilege", "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege"}
			if entry.name == Engine {
				privileges = append(privileges, "SeLoadDriverPrivilege")
			}
			for _, name := range privileges {
				part, _ := windows.UTF16FromString(name)
				names = append(names, part...)
			}
			names = append(names, 0)
			ptr := &names[0]
			err = windows.ChangeServiceConfig2(s.Handle, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, (*byte)(unsafe.Pointer(&ptr)))
		}
		s.Close()
		if err != nil {
			return err
		}
	}
	return SetOwner(c.Owner)
}
func Uninstall(ctx context.Context) error {
	if err := Stop(ctx, Control); err != nil && err != windows.ERROR_SERVICE_NOT_ACTIVE {
		return err
	}
	// The control clean stop has already stopped the engine through IPC.
	for _, name := range []string{Engine, Control} {
		s, err := open(name, windows.DELETE|windows.SERVICE_QUERY_STATUS)
		if err != nil {
			return err
		}
		status, err := s.Query()
		if err == nil && status.State != svc.Stopped {
			err = fmt.Errorf("%s is still running", name)
		}
		if err == nil {
			err = s.Delete()
		}
		s.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
