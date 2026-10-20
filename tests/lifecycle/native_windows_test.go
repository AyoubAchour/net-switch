package lifecycle_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/lifecycle"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/internal/service"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
)

type windowsActor struct {
	name, sid string
	token     windows.Token
	t         *testing.T
}

func (a *windowsActor) cleanup(fn func()) { a.t.Cleanup(fn) }

func (a *windowsActor) id() string { return a.sid }
func (a *windowsActor) command(exe string, args ...string) *exec.Cmd {
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(a.token), CreationFlags: windows.DETACHED_PROCESS, HideWindow: true}
	env, err := a.token.Environ(false)
	if err != nil {
		a.t.Fatal(err)
	}
	for _, name := range []string{"GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "NETSWITCH_LIFECYCLE_CI", "NETSWITCH_LIFECYCLE_DIR"} {
		env = append(env, name+"="+os.Getenv(name))
	}
	cmd.Env = env
	return cmd
}
func (a *windowsActor) close() {
	a.token.Close()
	name, _ := windows.UTF16PtrFromString(a.name)
	windows.NewLazySystemDLL("netapi32.dll").NewProc("NetUserDel").Call(0, uintptr(unsafe.Pointer(name)))
}
func newActor(t *testing.T, name string) actor {
	t.Helper()
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		t.Fatal(err)
	}
	password := "Ns!" + hex.EncodeToString(entropy[:]) + "9a"
	namep, _ := windows.UTF16PtrFromString(name)
	passwordp, _ := windows.UTF16PtrFromString(password)
	type userInfo struct {
		Name, Password *uint16
		Age, Privilege uint32
		Home, Comment  *uint16
		Flags          uint32
		Script         *uint16
	}
	info := userInfo{Name: namep, Password: passwordp, Privilege: 1, Flags: 0x10001}
	var parameter uint32
	result, _, _ := windows.NewLazySystemDLL("netapi32.dll").NewProc("NetUserAdd").Call(0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parameter)))
	if result != 0 {
		t.Fatalf("create disposable local user: code %d parameter %d", result, parameter)
	}
	domain, _ := windows.UTF16PtrFromString(".")
	var token windows.Token
	ok, _, err := windows.NewLazySystemDLL("advapi32.dll").NewProc("LogonUserW").Call(uintptr(unsafe.Pointer(namep)), uintptr(unsafe.Pointer(domain)), uintptr(unsafe.Pointer(passwordp)), 2, 0, uintptr(unsafe.Pointer(&token)))
	if ok == 0 {
		t.Fatal("log on disposable user:", err)
	}
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if token.IsElevated() {
		t.Fatal("test user is elevated")
	}
	t.Logf("standard user %s enrolled=%s", name, user.User.Sid.String())
	return &windowsActor{name: name, sid: user.User.Sid.String(), token: token, t: t}
}
func testData() string { return filepath.Join(os.Getenv("ProgramData"), "NetSwitch-Lifecycle-CI") }
func verifyPermissions(t *testing.T, owner, other actor) {
	t.Helper()
	exe, _ := os.Executable()
	for _, user := range []actor{owner, other} {
		b, err := user.command(exe, "client", "permissions").CombinedOutput()
		if err != nil {
			t.Fatalf("standard user permission probe: %v: %s", err, b)
		}
		t.Log(stringsafe(b))
	}
	// An owner can connect to the desktop pipe; another user cannot even
	// acquire its handle, before application-level authorization.
	if b, err := other.command(exe, "client", "desktop-denied").CombinedOutput(); err != nil {
		t.Fatal(err, string(b))
	}
}
func stringsafe(b []byte) string { return string(b) }
func permissionProbe() error {
	if lifecycle.Administrator() {
		return errors.New("permission probe was not standard-user")
	}
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(manager)
	for _, name := range []string{service.Control, service.Engine} {
		n, _ := windows.UTF16PtrFromString(name)
		for _, rights := range []uint32{windows.SERVICE_STOP, windows.SERVICE_CHANGE_CONFIG} {
			h, err := windows.OpenService(manager, n, rights)
			if err == nil {
				windows.CloseServiceHandle(h)
				return fmt.Errorf("%s granted forbidden service right %x", name, rights)
			}
			if err != windows.ERROR_ACCESS_DENIED {
				return err
			}
		}
		if name == service.Engine {
			h, err := windows.OpenService(manager, n, windows.SERVICE_START)
			if err == nil {
				windows.CloseServiceHandle(h)
				return errors.New("user may start engine")
			}
		}
	}
	// The actual endpoint must exist, otherwise ENOENT could fake a denial.
	if status, err := service.Query(service.Control); err != nil || !status.Running {
		return fmt.Errorf("permission precondition: %v", err)
	}
	path, _ := windows.UTF16PtrFromString(localipc.DefaultPath("desktop"))
	// Match the server's immutable pipe parameters so a mismatch cannot
	// masquerade as the ACL denial this probe is intended to prove.
	h, err := windows.CreateNamedPipe(path, windows.PIPE_ACCESS_DUPLEX, windows.PIPE_TYPE_BYTE, windows.PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, nil)
	if err == nil {
		windows.CloseHandle(h)
		return errors.New("user created competing pipe instance")
	}
	if err != windows.ERROR_ACCESS_DENIED {
		return fmt.Errorf("competing pipe failed for wrong reason: %w", err)
	}
	if _, err := os.ReadFile(filepath.Join(testData(), "owner.json")); err == nil {
		return errors.New("standard user read protected enrollment")
	}
	fmt.Println("standard-user service rights, pipe-instance ACL and store ACL denied")
	return nil
}
func desktopDenied() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := lifecycle.ConnectDesktop(ctx, false)
	if err == nil {
		c.Close()
		return errors.New("non-owner opened desktop pipe")
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return fmt.Errorf("desktop pipe denied for wrong reason: %w", err)
	}
	return nil
}
func probeMain([]string) int { return 2 }
func disableRecovery(t *testing.T) func() {
	t.Helper()
	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(service.Control)
	if err != nil {
		t.Fatal(err)
	}
	actions, err := s.RecoveryActions()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.NoAction}}, 600); err != nil {
		t.Fatal(err)
	}
	s.Close()
	return func() {
		m, err := mgr.Connect()
		if err != nil {
			t.Error(err)
			return
		}
		defer m.Disconnect()
		s, err := m.OpenService(service.Control)
		if err != nil {
			t.Error(err)
			return
		}
		defer s.Close()
		if err := s.SetRecoveryActions(actions, 600); err != nil {
			t.Error(err)
		}
	}
}

// SCM launches this one test executable as SYSTEM, so its children use real
// independent user tokens with CreateProcessAsUser. No product debug API exists.
func hostedMain(m *testing.M) (bool, int) {
	if len(os.Args) < 2 {
		return false, 0
	}
	switch os.Args[1] {
	case "suite-service":
		if !hosted() {
			return true, 2
		}
		if err := os.Chdir(os.Args[2]); err != nil {
			return true, 2
		}
		output := os.Args[3]
		log, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return true, 2
		}
		os.Stdout, os.Stderr = log, log
		code := 1
		os.Args = []string{os.Args[0], "-test.v", "-test.timeout=8m"}
		err = service.Run("NetSwitchLifecycleTests", func(_ context.Context, ready func()) error {
			ready()
			code = m.Run()
			_ = log.Sync()
			if err := os.WriteFile(output+".result", []byte(strconv.Itoa(code)), 0600); err != nil {
				return err
			}
			if code != 0 {
				return fmt.Errorf("lifecycle tests failed: %d", code)
			}
			return nil
		})
		if err != nil {
			fmt.Fprintln(log, err)
		}
		log.Close()
		return true, code
	case "run-hosted":
		if !hosted() {
			return true, 2
		}
		exe, _ := os.Executable()
		cwd, _ := os.Getwd()
		output := filepath.Join(os.Getenv("ProgramData"), "netswitch-lifecycle-test.log")
		mgr, err := mgr.Connect()
		if err != nil {
			fmt.Println(err)
			return true, 1
		}
		defer mgr.Disconnect()
		s, err := mgr.CreateService("NetSwitchLifecycleTests", exe, mgrConfig(), "suite-service", cwd, output)
		if err != nil {
			fmt.Println(err)
			return true, 1
		}
		defer s.Close()
		defer s.Delete()
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\NetSwitchLifecycleTests`, registry.SET_VALUE)
		if err != nil {
			fmt.Println(err)
			return true, 1
		}
		env := []string{}
		for _, name := range []string{"GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "NETSWITCH_LIFECYCLE_CI", "NETSWITCH_LIFECYCLE_DIR", "SystemRoot", "ProgramData"} {
			env = append(env, name+"="+os.Getenv(name))
		}
		err = key.SetStringsValue("Environment", env)
		key.Close()
		if err != nil {
			fmt.Println(err)
			return true, 1
		}
		if err := s.Start(); err != nil {
			fmt.Println(err)
			return true, 1
		}
		deadline := time.Now().Add(9 * time.Minute)
		for time.Now().Before(deadline) {
			state, err := s.Query()
			if err != nil {
				fmt.Println(err)
				return true, 1
			}
			if state.State == 1 {
				b, _ := os.ReadFile(output)
				fmt.Print(string(b))
				b, err = os.ReadFile(output + ".result")
				if err != nil {
					return true, 1
				}
				code, _ := strconv.Atoi(string(b))
				return true, code
			}
			time.Sleep(time.Second)
		}
		fmt.Println("test service timed out")
		return true, 1
	}
	return false, 0
}
func mgrConfig() mgr.Config {
	return mgr.Config{StartType: mgr.StartManual, ServiceStartName: "LocalSystem"}
}
