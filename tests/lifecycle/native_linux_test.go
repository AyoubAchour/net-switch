package lifecycle_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/tests/linux/inet"
)

type linuxActor struct {
	name, uid string
	number    uint32
	group     uint32
	t         *testing.T
	home      string
	closed    bool
}

func (a *linuxActor) cleanup(fn func()) { a.t.Cleanup(fn) }

func (a *linuxActor) id() string { return a.uid }
func (a *linuxActor) command(exe string, args ...string) *exec.Cmd {
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: a.number, Gid: a.group, NoSetGroups: false}}
	cmd.Env = append(os.Environ(), "HOME="+a.home, "USER="+a.name)
	return cmd
}
func (a *linuxActor) close() {
	if a.closed {
		return
	}
	a.closed = true
	u, err := checkedLinuxActor(a.name)
	var missing user.UnknownUserError
	if errors.As(err, &missing) {
		return
	}
	if err != nil || (a.uid != "" && u.Uid != a.uid) {
		a.t.Errorf("refuse disposable account cleanup for changed identity %s: %v", a.name, err)
		return
	}
	// Disabling linger alone does not join the user manager's exit. Stop its
	// service and slice before userdel, which refuses a UID with live processes.
	for _, args := range [][]string{
		{"loginctl", "disable-linger", a.name},
		{"systemctl", "stop", "user@" + u.Uid + ".service", "user-" + u.Uid + ".slice"},
		{"userdel", "--remove", a.name},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		b, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		cancel()
		if err != nil {
			a.t.Errorf("disposable account cleanup %v: %v: %s", args, err, b)
			return
		}
	}
	assertActorRemoved(a.t, a.name)
}
func newActor(t *testing.T, name string) actor {
	t.Helper()
	requireActorName(t, name)
	a := &linuxActor{name: name, t: t}
	_, err := user.Lookup(name)
	var missing user.UnknownUserError
	switch {
	case errors.As(err, &missing):
		if b, err := exec.Command("useradd", "--create-home", "--user-group", "--shell", "/bin/sh", "--comment", actorComment, name).CombinedOutput(); err != nil {
			t.Fatal("create disposable account", err, string(b))
		}
		t.Cleanup(a.close) // owns the account even if any following setup fails
	case err != nil:
		t.Fatal("lookup disposable account", err)
	default:
		if _, err := checkedLinuxActor(name); err != nil {
			t.Fatal("refuse existing account", err)
		}
		t.Cleanup(a.close)
		t.Logf("ACTOR_REUSED name=%s verified_unprivileged=true", name)
	}
	u, err := checkedLinuxActor(name)
	if err != nil {
		t.Fatal(err)
	}
	a.uid, a.home = u.Uid, u.HomeDir
	n, _ := strconv.ParseUint(u.Uid, 10, 32)
	g, _ := strconv.ParseUint(u.Gid, 10, 32)
	a.number, a.group = uint32(n), uint32(g)
	// The engine ACL probe needs only a different UID. M2's session tests
	// require linger, but starting a user manager here adds an unrelated lifetime.
	if name != "NSNativeOther" {
		if b, err := exec.Command("loginctl", "enable-linger", name).CombinedOutput(); err != nil {
			t.Fatal(err, string(b))
		}
	}
	return a
}

func checkedLinuxActor(name string) (*user.User, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return nil, err
	}
	uid, uidErr := strconv.ParseUint(u.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(u.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid < 1000 || gid < 1000 || u.Username != name || u.Name != actorComment || u.HomeDir != "/home/"+name {
		return nil, fmt.Errorf("unexpected disposable account: want_name=%q name=%q uid=%q gid=%q want_comment=%q comment=%q home=%q uid_error=%v gid_error=%v", name, u.Username, u.Uid, u.Gid, actorComment, u.Name, u.HomeDir, uidErr, gidErr)
	}
	group, err := user.LookupGroupId(u.Gid)
	if err != nil || group.Name != name {
		return nil, fmt.Errorf("%s has an unexpected primary group: gid=%q group=%+v error=%v", name, u.Gid, group, err)
	}
	groups, err := u.GroupIds()
	if err != nil || len(groups) != 1 || groups[0] != u.Gid {
		return nil, fmt.Errorf("%s has unexpected supplementary groups: primary=%q groups=%v error=%v", name, u.Gid, groups, err)
	}
	b, err := exec.Command("passwd", "--status", name).Output()
	fields := strings.Fields(string(b))
	if err != nil || len(fields) < 2 || fields[0] != name || fields[1] != "L" {
		return nil, fmt.Errorf("%s does not have the expected locked password: passwd_status=%q error=%v", name, strings.TrimSpace(string(b)), err)
	}
	return u, nil
}

func assertActorRemoved(t *testing.T, name string) {
	t.Helper()
	_, err := user.Lookup(name)
	var missing user.UnknownUserError
	if !errors.As(err, &missing) {
		t.Errorf("disposable account %s remains after cleanup: %v", name, err)
	} else {
		t.Logf("ACTOR_REMOVED name=%s", name)
	}
}
func testData() string { return "/var/lib/netswitch-lifecycle-ci" }
func verifyPermissions(t *testing.T, owner, other actor) {
	t.Helper()
	exe, _ := os.Executable()
	for _, actor := range []actor{owner, other} {
		if b, err := actor.command(exe, "client", "permissions").CombinedOutput(); err != nil {
			t.Fatal(err, string(b))
		}
	}
	probe := other.command(exe, "client", "desktop-denied")
	// GID zero alone is not root authority. The private socket must grant
	// the named owner UID, not every process that happens to share its group.
	probe.SysProcAttr.Credential.Gid = 0
	probe.SysProcAttr.Credential.Groups = []uint32{0}
	if b, err := probe.CombinedOutput(); err != nil {
		t.Fatal("private owner socket ACL", err, string(b))
	}
	c := openClient(t, other, true)
	defer c.input.Close()
	if _, err := c.call(t, "routing", map[string]any{"on": true}); err == nil {
		t.Fatal("SO_PEERCRED accepted another UID")
	}
}
func permissionProbe() error {
	if os.Geteuid() == 0 {
		return errors.New("permission probe ran as root")
	}
	info, err := os.Stat(localipc.DefaultPath("status"))
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0666 {
		return fmt.Errorf("desktop socket mode is %o", info.Mode().Perm())
	}
	if _, err := os.ReadFile(filepath.Join(testData(), "owner.json")); !errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("protected enrollment must fail with permission denied, got %v", err)
	}
	fmt.Println("standard-user store access denied; desktop socket permits status")
	return nil
}
func desktopDenied() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := localipc.Dial(ctx, localipc.Endpoint{Path: localipc.DefaultPath("desktop"), Kind: "desktop"})
	if err == nil {
		c.Close()
		return errors.New("non-owner opened private owner socket")
	}
	if !errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("owner socket denial was not permissions: %w", err)
	}
	return nil
}
func legacyMutex() error     { return errors.New("Windows only") }
func probeMain([]string) int { return 2 }
func hostedMain(*testing.M) (bool, int) {
	if len(os.Args) == 3 && os.Args[1] == "tun-relay" && hosted() {
		if err := tunRelay(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return true, 1
		}
		return true, 0
	}
	if len(os.Args) > 1 && os.Args[1] == "serve" && hosted() {
		if err := inet.Main(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return true, 1
		}
		return true, 0
	}
	return false, 0
}
func disableRecovery(t *testing.T) func() {
	t.Helper()
	dir := "/run/systemd/system/netswitch.service.d"
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "lifecycle-test.conf")
	if err := os.WriteFile(path, []byte("[Service]\nRestart=no\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if b, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		t.Fatal(err, string(b))
	}
	return func() {
		_ = os.Remove(path)
		if b, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
			t.Error(err, string(b))
		}
	}
}
