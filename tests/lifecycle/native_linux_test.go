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
	"syscall"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/tests/linux/inet"
)

type linuxActor struct {
	name, uid string
	number    uint32
	t         *testing.T
	home      string
}

func (a *linuxActor) cleanup(fn func()) { a.t.Cleanup(fn) }

func (a *linuxActor) id() string { return a.uid }
func (a *linuxActor) command(exe string, args ...string) *exec.Cmd {
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: a.number, Gid: a.number, NoSetGroups: false}}
	cmd.Env = append(os.Environ(), "HOME="+a.home, "USER="+a.name)
	return cmd
}
func (a *linuxActor) close() {
	_ = exec.Command("loginctl", "disable-linger", a.name).Run()
	_ = exec.Command("userdel", a.name).Run()
}
func newActor(t *testing.T, name string) actor {
	t.Helper()
	if b, err := exec.Command("useradd", "--create-home", name).CombinedOutput(); err != nil {
		t.Fatal(err, string(b))
	}
	u, err := user.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := exec.Command("loginctl", "enable-linger", name).CombinedOutput(); err != nil {
		t.Fatal(err, string(b))
	}
	n, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	return &linuxActor{name: name, uid: u.Uid, number: uint32(n), home: u.HomeDir, t: t}
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
