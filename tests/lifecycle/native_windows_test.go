package lifecycle_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
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
	closed    bool
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
	if a.closed {
		return
	}
	a.closed = true
	if a.token != 0 {
		if err := a.token.Close(); err != nil {
			a.t.Error("close disposable logon token", err)
		}
	}
	if err := checkedWindowsActor(a.name); err != nil {
		if !errors.Is(err, syscall.Errno(2221)) { // NERR_UserNotFound
			a.t.Errorf("refuse disposable account cleanup %s: %v", a.name, err)
		}
		return
	}
	name, _ := windows.UTF16PtrFromString(a.name)
	result, _, _ := windows.NewLazySystemDLL("netapi32.dll").NewProc("NetUserDel").Call(0, uintptr(unsafe.Pointer(name)))
	if result != 0 {
		a.t.Errorf("delete disposable account %s: code %d", a.name, result)
		return
	}
	assertActorRemoved(a.t, a.name)
}

type actorUserInfo struct {
	Name, Password *uint16
	Age, Privilege uint32
	Home, Comment  *uint16
	Flags          uint32
	Script         *uint16
}

func newActor(t *testing.T, name string) actor {
	t.Helper()
	requireActorName(t, name)
	a := &windowsActor{name: name, t: t}
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		t.Fatal(err)
	}
	password := "Ns!" + hex.EncodeToString(entropy[:]) + "9a"
	namep, _ := windows.UTF16PtrFromString(name)
	passwordp, _ := windows.UTF16PtrFromString(password)
	comment, _ := windows.UTF16PtrFromString(actorComment)
	info := actorUserInfo{Name: namep, Password: passwordp, Privilege: 1, Flags: 0x10201, Comment: comment}
	var parameter uint32
	result, _, _ := windows.NewLazySystemDLL("netapi32.dll").NewProc("NetUserAdd").Call(0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parameter)))
	switch result {
	case 0:
		t.Cleanup(a.close) // before LogonUser or token inspection can fail
	case 2224: // NERR_UserExists: verify before resetting any password
		if err := checkedWindowsActor(name); err != nil {
			t.Fatal("refuse existing account", err)
		}
		t.Cleanup(a.close)
		passwordInfo := struct{ Password *uint16 }{passwordp} // USER_INFO_1003
		code, _, _ := windows.NewLazySystemDLL("netapi32.dll").NewProc("NetUserSetInfo").Call(0, uintptr(unsafe.Pointer(namep)), 1003, uintptr(unsafe.Pointer(&passwordInfo)), uintptr(unsafe.Pointer(&parameter)))
		if code != 0 {
			t.Fatalf("reset verified disposable account password: code %d parameter %d", code, parameter)
		}
		t.Logf("ACTOR_REUSED name=%s verified_unprivileged=true", name)
	default:
		t.Fatalf("create disposable local user: code %d parameter %d", result, parameter)
	}
	if err := checkedWindowsActor(name); err != nil {
		t.Fatal(err)
	}
	domain, _ := windows.UTF16PtrFromString(".")
	var token windows.Token
	ok, _, err := windows.NewLazySystemDLL("advapi32.dll").NewProc("LogonUserW").Call(uintptr(unsafe.Pointer(namep)), uintptr(unsafe.Pointer(domain)), uintptr(unsafe.Pointer(passwordp)), 2, 0, uintptr(unsafe.Pointer(&token)))
	if ok == 0 {
		t.Fatal("log on disposable user:", err)
	}
	a.token = token
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	var elevationType, returned uint32
	if err := windows.GetTokenInformation(token, windows.TokenElevationType, (*byte)(unsafe.Pointer(&elevationType)), 4, &returned); err != nil {
		t.Fatal("read disposable token elevation type", err)
	}
	if err := checkActorToken(elevationType, token.IsElevated()); err != nil {
		t.Fatal(err)
	}
	if err := checkActorTokenPrivileges(token); err != nil {
		t.Fatal("disposable account rights", err)
	}
	t.Logf("ACTOR_TOKEN name=%s elevation_type=%d unsplit=true", name, elevationType)
	t.Logf("standard user %s enrolled=%s", name, user.User.Sid.String())
	a.sid = user.User.Sid.String()
	return a
}

func checkedWindowsActor(name string) error {
	namep, _ := windows.UTF16PtrFromString(name)
	var b *byte
	if err := windows.NetUserGetInfo(nil, namep, 1, &b); err != nil {
		return err
	}
	defer windows.NetApiBufferFree(b)
	u := (*actorUserInfo)(unsafe.Pointer(b))
	if err := checkWindowsActorInfo(name, u); err != nil {
		return err
	}
	// IsElevated alone misses a split administrator token. Check all direct
	// and indirect local memberships before reusing the account or changing it.
	var groups *byte
	var read, total uint32
	code, _, _ := windows.NewLazySystemDLL("netapi32.dll").NewProc("NetUserGetLocalGroups").Call(0, uintptr(unsafe.Pointer(namep)), 0, 1, uintptr(unsafe.Pointer(&groups)), 64<<10, uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)))
	if groups != nil {
		defer windows.NetApiBufferFree(groups)
	}
	if code != 0 || read != total || read > 64 {
		return fmt.Errorf("read disposable account groups: code=%d read=%d total=%d", code, read, total)
	}
	var observedGroups []string
	for _, group := range unsafe.Slice((**uint16)(unsafe.Pointer(groups)), read) {
		groupName := windows.UTF16PtrToString(group)
		sid, _, _, err := windows.LookupSID("", groupName)
		if err != nil {
			return fmt.Errorf("%s local group %q SID lookup: %w", name, groupName, err)
		}
		if err := checkWindowsActorGroup(name, groupName, sid.String()); err != nil {
			return err
		}
		observedGroups = append(observedGroups, groupName+"="+sid.String())
	}
	fmt.Printf("ACTOR_VERIFIED name=%q privilege=%d flags=%#x groups=%q\n", name, u.Privilege, u.Flags, observedGroups)
	return nil
}

func checkWindowsActorInfo(name string, u *actorUserInfo) error {
	// NetUserAdd requires USER_PRIV_USER (1), but that input is not a
	// round-trip invariant: hosted Windows reports 0 for this normal account.
	// Both 0 and 1 are non-admin summaries. Group checks remain independent,
	// so a filtered administrator token cannot qualify through this field.
	if windows.UTF16PtrToString(u.Name) != name || windows.UTF16PtrToString(u.Comment) != actorComment || u.Privilege > 1 || u.Flags&0x200 == 0 || u.Flags&0x2 != 0 {
		return fmt.Errorf("unexpected disposable account: want_name=%q name=%q want_comment=%q comment=%q privilege=%d flags=%#x normal=%t disabled=%t home=%q script=%q", name, windows.UTF16PtrToString(u.Name), actorComment, windows.UTF16PtrToString(u.Comment), u.Privilege, u.Flags, u.Flags&0x200 != 0, u.Flags&0x2 != 0, windows.UTF16PtrToString(u.Home), windows.UTF16PtrToString(u.Script))
	}
	return nil
}

func checkWindowsActorGroup(name, group, sid string) error {
	if sid != "S-1-5-32-545" { // BUILTIN Users, any locale
		return fmt.Errorf("%s has unexpected local group membership: name=%q sid=%q", name, group, sid)
	}
	return nil
}

func checkActorToken(kind uint32, elevated bool) error {
	if kind != 1 || elevated { // TokenElevationTypeDefault: no linked token
		return fmt.Errorf("disposable token must be unelevated and unsplit: type=%d elevated=%t", kind, elevated)
	}
	return nil
}

// Check every token, including UAC-off tokens where "Default" is not evidence
// against directly granted admin rights. Disabled privileges still count: the
// process can enable them without elevating. These five are standard-user rights.
func checkActorTokenPrivileges(token windows.Token) error {
	allowed := map[windows.LUID]string{}
	for _, name := range []string{"SeChangeNotifyPrivilege", "SeShutdownPrivilege", "SeUndockPrivilege", "SeIncreaseWorkingSetPrivilege", "SeTimeZonePrivilege"} {
		var id windows.LUID
		if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &id); err != nil {
			return err
		}
		allowed[id] = name
	}
	var size uint32
	err := windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &size)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || size < 4 || size > 64<<10 {
		return fmt.Errorf("query token privileges: size=%d error=%v", size, err)
	}
	words := make([]uint64, (size+7)/8)
	if err := windows.GetTokenInformation(token, windows.TokenPrivileges, (*byte)(unsafe.Pointer(&words[0])), uint32(len(words)*8), &size); err != nil {
		return err
	}
	privileges := (*windows.Tokenprivileges)(unsafe.Pointer(&words[0]))
	if size < 4 || uint64(size) > uint64(len(words)*8) || uint64(privileges.PrivilegeCount)*uint64(unsafe.Sizeof(windows.LUIDAndAttributes{}))+4 > uint64(size) {
		return fmt.Errorf("invalid token privileges: size=%d count=%d", size, privileges.PrivilegeCount)
	}
	return checkActorPrivileges(privileges.AllPrivileges(), allowed)
}

func checkActorPrivileges(privileges []windows.LUIDAndAttributes, allowed map[windows.LUID]string) error {
	var names []string
	for _, p := range privileges {
		name, ok := allowed[p.Luid]
		if !ok {
			return fmt.Errorf("unexpected privilege LUID=%+v attributes=%#x (UAC-independent check)", p.Luid, p.Attributes)
		}
		names = append(names, name)
	}
	fmt.Printf("ACTOR_PRIVILEGES standard_user_only=true rights=%q\n", names)
	return nil
}

func assertActorRemoved(t *testing.T, name string) {
	t.Helper()
	namep, _ := windows.UTF16PtrFromString(name)
	var b *byte
	err := windows.NetUserGetInfo(nil, namep, 1, &b)
	if b != nil {
		windows.NetApiBufferFree(b)
	}
	if !errors.Is(err, syscall.Errno(2221)) {
		t.Errorf("disposable account %s remains after cleanup: %v", name, err)
	} else {
		t.Logf("ACTOR_REMOVED name=%s", name)
	}
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
	if _, err := os.ReadFile(filepath.Join(testData(), "owner.json")); !errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("protected enrollment must fail with permission denied, got %v", err)
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
func legacyMutex() error {
	if lifecycle.Administrator() {
		return errors.New("mutex squatter is elevated")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	digest := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(testData())) + "\x00engine"))
	name, _ := windows.UTF16PtrFromString(fmt.Sprintf(`Global\NetSwitch-%x`, digest[:16]))
	h, err := windows.CreateMutex(nil, true, name)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	defer windows.ReleaseMutex(h)
	fmt.Println("held")
	_, err = io.Copy(io.Discard, os.Stdin)
	return err
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
	restore := sync.OnceFunc(func() {
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
	})
	t.Cleanup(restore)
	return restore
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
		os.Args = []string{os.Args[0], "-test.v", "-test.timeout=22m"}
		if filter := os.Getenv("NETSWITCH_LIFECYCLE_FILTER"); filter != "" {
			os.Args = append(os.Args, "-test.run="+filter)
		}
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
		if err := os.Remove(output + ".result"); err != nil && !os.IsNotExist(err) {
			fmt.Println(err)
			return true, 1
		}
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
		for _, name := range []string{"GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "NETSWITCH_LIFECYCLE_CI", "NETSWITCH_LIFECYCLE_DIR", "NETSWITCH_LIFECYCLE_FILTER", "NETSWITCH_NATIVE_CI", "NETSWITCH_NATIVE_FAULTS", "SystemRoot", "ProgramData"} {
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
		deadline := time.Now().Add(16 * time.Minute)
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
