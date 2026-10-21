package lifecycle_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

type logindLoginInfo struct {
	Session string
	UID     uint32
	Child   int
}

// This helper is run directly from the compiled test binary by systemd-run,
// never by a nested go test. PAM opens/closes the real logind session; the
// helper does not call CreateSession or ReleaseSession itself.
func TestHostedLogindLoginHelper(t *testing.T) {
	if !hosted() || os.Getenv("NETSWITCH_LOGIND_LOGIN_HELPER") != "1" {
		t.Skip("helper for the disposable hosted PAM logout test")
	}
	id := os.Getenv("XDG_SESSION_ID")
	if id == "" || os.Geteuid() == 0 {
		t.Fatal("PAM must establish a real non-root session")
	}
	child := exec.Command("sleep", "240")
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	// Nil stdio means /dev/null, so the leftover neither holds the login's
	// pipes open nor dies with its terminal. The parent verifies its cgroup.
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	info := logindLoginInfo{Session: id, UID: uint32(os.Geteuid()), Child: child.Process.Pid}
	b, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("NETSWITCH_LOGIN " + string(b))
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		t.Fatal(err)
	}
	// Exit normally when stdin closes, leaving sleep in this session's scope.
}

type logindLogin struct {
	info   logindLoginInfo
	input  io.WriteCloser
	done   chan struct{}
	err    error
	log    bytes.Buffer
	output bytes.Buffer
}

func requireLeftoverSessions(t *testing.T) {
	t.Helper()
	bus, err := dbus.SystemBus()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var kill dbus.Variant
	err = bus.Object("org.freedesktop.login1", "/org/freedesktop/login1").CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, "org.freedesktop.login1.Manager", "KillUserProcesses").Store(&kill)
	if err != nil || kill.Value() != false {
		t.Fatal("logout regression requires KillUserProcesses=no on the disposable runner", kill.Value(), err)
	}
}

func requireOnlineManager(t *testing.T, owner uint32) {
	t.Helper()
	if os.Getenv("NETSWITCH_EXPECT_LOGIND_MANAGER") != "1" {
		return
	}
	bus, err := dbus.SystemBus()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var rows []struct {
		ID   string
		UID  uint32
		User string
		Seat string
		Path dbus.ObjectPath
	}
	if err := bus.Object("org.freedesktop.login1", "/org/freedesktop/login1").CallWithContext(ctx, "org.freedesktop.login1.Manager.ListSessions", 0).Store(&rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.UID != owner {
			continue
		}
		var properties map[string]dbus.Variant
		if err := bus.Object("org.freedesktop.login1", row.Path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0, "org.freedesktop.login1.Session").Store(&properties); err != nil {
			t.Fatal(err)
		}
		if properties["Class"].Value() == "manager" && properties["State"].Value() == "online" {
			t.Logf("LOGIND_MANAGER session=%s remains online after owner logout", row.ID)
			return
		}
	}
	t.Fatal("new-systemd regression requires the owner's manager session to remain online")
}

func openLogindLogin(t *testing.T, a *linuxActor, label string) *logindLogin {
	t.Helper()
	if !hosted() {
		t.Fatal("refusing to create logind sessions outside hosted CI")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	unit := fmt.Sprintf("netswitch-logout-%d-%s", os.Getpid(), label)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	args := []string{"--quiet", "--wait", "--pipe", "--collect", "--unit=" + unit,
		"--uid=" + a.name, "--property=PAMName=login", "--property=KillMode=mixed",
		"--setenv=GITHUB_ACTIONS=true", "--setenv=RUNNER_ENVIRONMENT=github-hosted",
		"--setenv=NETSWITCH_LIFECYCLE_CI=1", "--setenv=NETSWITCH_LOGIND_LOGIN_HELPER=1",
		exe, "-test.run=^TestHostedLogindLoginHelper$", "-test.v", "-test.timeout=90s"}
	cmd := exec.CommandContext(ctx, "systemd-run", args...)
	l := &logindLogin{done: make(chan struct{})}
	cmd.Stderr = &l.log
	l.input, err = cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	ready := make(chan string, 1)
	go func() {
		scan := bufio.NewScanner(out)
		for scan.Scan() {
			fmt.Fprintln(&l.output, scan.Text())
			if line, ok := strings.CutPrefix(scan.Text(), "NETSWITCH_LOGIN "); ok {
				ready <- line
			}
		}
		l.err = cmd.Wait()
		close(l.done)
	}()
	t.Cleanup(func() {
		_ = l.input.Close()
		cancel()
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		// The transient service and its session scope are distinct units.
		_ = exec.CommandContext(cleanup, "systemctl", "stop", unit).Run()
		if l.info.Session != "" {
			if b, err := exec.CommandContext(cleanup, "loginctl", "terminate-session", l.info.Session).CombinedOutput(); err != nil {
				t.Errorf("terminate test session %s: %v %s", l.info.Session, err, b)
			}
		}
	})
	select {
	case line := <-ready:
		if err := json.Unmarshal([]byte(line), &l.info); err != nil {
			t.Fatal(err)
		}
	case <-l.done:
		diagnostic, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		b, _ := exec.CommandContext(diagnostic, "journalctl", "-u", unit, "--no-pager", "--lines=30").CombinedOutput()
		t.Logf("PAM helper unit diagnostics:\n%s", b)
		t.Fatal("PAM login helper exited before ready", l.err, l.log.String(), l.output.String())
	case <-time.After(20 * time.Second):
		t.Fatal("PAM login helper did not report a session")
	}
	if l.info.UID != a.number || l.info.Session == "" || l.info.Child <= 1 {
		t.Fatal("login helper identity", l.info)
	}
	t.Logf("real PAM session=%s owner=%d leftover=%d", l.info.Session, l.info.UID, l.info.Child)
	return l
}

func (l *logindLogin) logout(t *testing.T) {
	t.Helper()
	if err := l.input.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-l.done:
		if l.err != nil {
			t.Fatal("PAM login did not exit normally", l.err, l.log.String(), l.output.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("PAM logout did not finish")
	}
}

func (l *logindLogin) state(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	bus, err := dbus.SystemBus()
	if err != nil {
		t.Fatal(err)
	}
	var path dbus.ObjectPath
	if err = bus.Object("org.freedesktop.login1", "/org/freedesktop/login1").CallWithContext(ctx, "org.freedesktop.login1.Manager.GetSession", 0, l.info.Session).Store(&path); err != nil {
		t.Fatal("test session must still exist", l.info, err)
	}
	var props map[string]dbus.Variant
	if err = bus.Object("org.freedesktop.login1", path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0, "org.freedesktop.login1.Session").Store(&props); err != nil {
		t.Fatal(err)
	}
	var user struct {
		UID  uint32
		Path dbus.ObjectPath
	}
	if err = props["User"].Store(&user); err != nil || user.UID != l.info.UID {
		t.Fatal("logind session owner mismatch", user, err)
	}
	scope, ok := props["Scope"].Value().(string)
	if !ok || scope == "" {
		t.Fatal("session has no scope", props)
	}
	proc := "/proc/" + strconv.Itoa(l.info.Child)
	cgroup, err := os.ReadFile(proc + "/cgroup")
	if err != nil || !strings.Contains(string(cgroup), "/"+scope+"\n") {
		t.Fatal("leftover process must remain in the session scope", l.info, string(cgroup), err)
	}
	stat, err := os.ReadFile(proc + "/stat")
	if err != nil {
		t.Fatal("leftover process vanished", err)
	}
	end := strings.LastIndexByte(string(stat), ')')
	if end < 0 || len(stat) <= end+2 || stat[end+2] == 'Z' || stat[end+2] == 'X' {
		t.Fatal("leftover process must be alive, not a zombie", string(stat))
	}
	state, ok := props["State"].Value().(string)
	if !ok {
		t.Fatal("invalid session state", props)
	}
	return state
}

func (l *logindLogin) assertState(t *testing.T, expected ...string) {
	t.Helper()
	state := l.state(t)
	for _, want := range expected {
		if state == want {
			return
		}
	}
	t.Fatalf("session %s state=%s; want %v", l.info.Session, state, expected)
}

func (l *logindLogin) waitClosing(t *testing.T) {
	t.Helper()
	// logind may delay ReleaseSession for 20 seconds after PAM closes.
	wait(t, "PAM logout enters closing with leftover process", 35*time.Second, func() bool { return l.state(t) == "closing" })
}
