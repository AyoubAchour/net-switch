// These tests install real services and kill processes. They are deliberately
// gated to disposable hosted runners, never a developer's live router.
package lifecycle_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/lifecycle"
	"github.com/AyoubAchour/net-switch/internal/lines"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/internal/service"
	linuxbox "github.com/AyoubAchour/net-switch/tests/linux/engine/singbox"
)

func hosted() bool {
	return os.Getenv("GITHUB_ACTIONS") == "true" && os.Getenv("RUNNER_ENVIRONMENT") == "github-hosted" && os.Getenv("NETSWITCH_LIFECYCLE_CI") == "1"
}
func TestMain(m *testing.M) {
	if handled, code := hostedMain(m); handled {
		os.Exit(code)
	}
	if len(os.Args) > 1 && os.Args[1] == "client" {
		if !hosted() {
			os.Exit(2)
		}
		os.Exit(clientMain(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "engine-probe" {
		if !hosted() {
			os.Exit(2)
		}
		os.Exit(probeMain(os.Args[2:]))
	}
	os.Exit(m.Run())
}
func clientMain(args []string) int {
	if len(args) > 0 && args[0] == "permissions" {
		if err := permissionProbe(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	if len(args) > 0 && args[0] == "desktop-denied" {
		if err := desktopDenied(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	if len(args) > 0 && args[0] == "engine-denied" {
		if err := engineDenied(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	statusOnly := len(args) > 0 && args[0] == "status"
	rpc, err := lifecycle.ConnectDesktop(ctx, statusOnly)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer rpc.Close()
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 4096), 1<<20)
	for scan.Scan() {
		var request map[string]any
		if json.Unmarshal(scan.Bytes(), &request) != nil {
			return 2
		}
		var result any
		err := rpc.Call(ctx, request, &result)
		out := map[string]any{"result": result}
		if err != nil {
			out["error"] = err.Error()
		}
		if json.NewEncoder(os.Stdout).Encode(out) != nil {
			return 1
		}
	}
	return 0
}

type actor interface {
	command(string, ...string) *exec.Cmd
	id() string
	close()
	cleanup(func())
}
type client struct {
	cmd      *exec.Cmd
	input    io.WriteCloser
	output   *bufio.Reader
	stderr   bytes.Buffer
	waitOnce sync.Once
	waitErr  error
}

func (c *client) wait() error { c.waitOnce.Do(func() { c.waitErr = c.cmd.Wait() }); return c.waitErr }

func openClient(t *testing.T, user actor, status bool) *client {
	t.Helper()
	exe, _ := os.Executable()
	args := []string{"client"}
	if status {
		args = append(args, "status")
	}
	c := &client{cmd: user.command(exe, args...)}
	var err error
	c.input, err = c.cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	c.output = bufio.NewReader(out)
	c.cmd.Stderr = &c.stderr
	if err = c.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	user.cleanup(func() { c.input.Close(); _ = c.cmd.Process.Kill(); _ = c.wait() })
	return c
}
func (c *client) call(t *testing.T, method string, extra map[string]any) (json.RawMessage, error) {
	t.Helper()
	if extra == nil {
		extra = map[string]any{}
	}
	extra["method"] = method
	if err := json.NewEncoder(c.input).Encode(extra); err != nil {
		return nil, err
	}
	line, err := c.output.ReadBytes('\n')
	if err != nil {
		_ = c.cmd.Process.Kill()
		exit := c.wait()
		return nil, fmt.Errorf("client exited: %w; process=%v state=%v stderr=%s", err, exit, c.cmd.ProcessState, c.stderr.String())
	}
	var reply struct {
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	if err = json.Unmarshal(line, &reply); err != nil {
		return nil, err
	}
	if reply.Error != "" {
		return nil, fmt.Errorf("%s", reply.Error)
	}
	return reply.Result, nil
}
func (c *client) must(t *testing.T, method string, extra map[string]any, out any) {
	t.Helper()
	b, err := c.call(t, method, extra)
	if err != nil {
		t.Fatal(method, err)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatal(err)
		}
	}
}

type status struct {
	Routing    string  `json:"routing"`
	Instance   string  `json:"engineInstanceId"`
	ControlPID uint32  `json:"controlPID"`
	DesktopPID uint32  `json:"desktopPID"`
	Error      *string `json:"error"`
}

func getStatus(t *testing.T, c *client) status {
	t.Helper()
	var s status
	c.must(t, "status", nil, &s)
	return s
}
func wait(t *testing.T, label string, duration time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("timeout: " + label)
}
func api(t *testing.T, url, token, method, route, body string) (int, []byte) {
	t.Helper()
	r, err := http.NewRequest(method, url+strings.TrimPrefix(route, "/"), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("X-Token", token)
	r.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Timeout: 20 * time.Second}).Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if len(response.Cookies()) != 0 {
		t.Fatal("HTTP emitted a cookie")
	}
	b, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, b
}
func fixture(t *testing.T, dir string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		path, err := filepath.Abs("../../engine/sing-box.exe")
		if err != nil {
			t.Fatal(err)
		}
		return path
	}
	version, err := linuxbox.PinnedVersion("../../packaging/versions.json")
	if err != nil {
		t.Fatal(err)
	}
	pin, err := linuxbox.LookupPin("../../tests/linux/sing-box-linux.json", version, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	b, err := linuxbox.Download(ctx, pin)
	if err != nil {
		t.Fatal(err)
	}
	if err = linuxbox.Extract(b, filepath.Join(dir, "adapter")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "adapter", "sing-box")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(content)
	if err = os.WriteFile(filepath.Join(dir, "adapter", "SHA256SUMS.txt"), []byte(hex.EncodeToString(hash[:])+"  sing-box\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestRealServices(t *testing.T) {
	if !hosted() {
		t.Skip("real services run only on disposable hosted runners")
	}
	if !lifecycle.Administrator() {
		t.Fatal("lifecycle harness must be elevated")
	}
	dir := os.Getenv("NETSWITCH_LIFECYCLE_DIR")
	if !filepath.IsAbs(dir) {
		t.Fatal("missing executable directory")
	}
	for _, name := range []string{"netswitch", "netswitch-engine", "netswitch-desktop", "netswitchctl"} {
		path := filepath.Join(dir, binary(name))
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		arg := "version"
		if name == "netswitch" || name == "netswitch-desktop" {
			arg = "--version"
		}
		version, err := exec.Command(path, arg).CombinedOutput()
		if err != nil {
			t.Fatal(err, string(version))
		}
		t.Logf("executable=%s sha256=%x version=%s", path, sum, strings.TrimSpace(string(version)))
	}
	data := testData()
	if err := lifecycle.PrepareDirectory(data); err != nil {
		t.Fatal(err)
	}
	owner, other := newActor(t, "NSLifecycleOwner"), newActor(t, "NSLifecycleOther")
	t.Cleanup(owner.close)
	t.Cleanup(other.close)
	adapter := fixture(t, dir)
	config := lifecycle.Config{Directory: dir, Data: data, Adapter: adapter, Mode: "proxy"}
	if err := lifecycle.Save(filepath.Join(data, "service-config.json"), config); err != nil {
		t.Fatal(err)
	}
	nic, address := primaryInterface(t)
	if err := lifecycle.Save(filepath.Join(data, "settings.json"), map[string]any{"lines": []lines.Line{{ID: "a1", Alias: nic, Label: "Test line", Weight: 1}}, "ipv6": "off", "checkForUpdates": false}); err != nil {
		t.Fatal(err)
	}
	echo := echoServer(t, address)
	if err := service.Install(service.Config{Directory: dir, Data: data}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 45*time.Second)
		defer stop()
		if err := service.Uninstall(cleanup); err != nil {
			t.Log("service cleanup:", err)
		}
		for _, name := range []string{"NetSwitch.log", "NetSwitchEngine.log"} {
			if b, err := os.ReadFile(filepath.Join(data, name)); err == nil {
				t.Logf("%s:\n%s", name, b)
			}
		}
	})
	if err := service.Start(ctx, service.Control); err != nil {
		t.Fatal(err)
	}
	t.Run("pending-enrollment-and-sign-in", func(t *testing.T) {
		readonly := openClient(t, other, true)
		s := getStatus(t, readonly)
		if s.Routing != "off" {
			t.Fatal("routing started before owner enrollment", s)
		}
		if _, err := readonly.call(t, "routing", map[string]any{"on": true}); err == nil {
			t.Fatal("pending status client controlled routing")
		}
	})
	if err := service.Stop(ctx, service.Control); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.Enroll(ctx, data, owner.id()); err != nil {
		t.Fatal(err)
	}
	if err := service.SetOwner(owner.id()); err != nil {
		t.Fatal(err)
	}
	if err := service.Start(ctx, service.Control); err != nil {
		t.Fatal(err)
	}
	c := openClient(t, owner, false)
	var session struct {
		Token string `json:"token"`
		URL   string `json:"url"`
	}
	c.must(t, "session", nil, &session)
	t.Run("non-owner-and-native-permissions", func(t *testing.T) {
		readonly := openClient(t, other, true)
		_ = getStatus(t, readonly)
		for _, method := range []string{"session", "pair", "routing", "signin"} {
			if _, err := readonly.call(t, method, nil); err == nil {
				t.Fatal("status client accepted", method)
			}
		}
		verifyPermissions(t, owner, other)
		output, err := other.command(filepath.Join(dir, binary("netswitch-desktop")), "--background").CombinedOutput()
		if err != nil || !strings.Contains(string(output), "status only") {
			t.Fatal("non-owner desktop did not offer status only", err, string(output))
		}
	})
	t.Run("pairing-and-bearer", func(t *testing.T) {
		var code string
		c.must(t, "pair", nil, &code)
		status, _ := api(t, session.URL, "", "GET", "/api/state", "")
		if status != 401 {
			t.Fatal("anonymous API accepted", status)
		}
		status, b := api(t, session.URL, "", "POST", "/api/pair", `{"code":"`+code+`"}`)
		if status != 200 {
			t.Fatalf("pairing failed %d", status)
		}
		var paired struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(b, &paired); err != nil {
			t.Fatal(err)
		}
		if len(paired.Token) != 64 {
			t.Fatal("token is not 256 bits")
		}
		status, _ = api(t, session.URL, "", "POST", "/api/pair", `{"code":"`+code+`"}`)
		if status != 401 {
			t.Fatal("code reused")
		}
		status, _ = api(t, session.URL, paired.Token, "GET", "/api/state", "")
		if status != 200 {
			t.Fatal("paired bearer refused")
		}
		var next string
		c.must(t, "pair", nil, &next)
		wrong := "000000"
		if wrong == next {
			wrong = "000001"
		}
		for range 3 {
			status, _ = api(t, session.URL, "", "POST", "/api/pair", `{"code":"`+wrong+`"}`)
			if status != 401 {
				t.Fatal("wrong code accepted")
			}
		}
		status, _ = api(t, session.URL, "", "POST", "/api/pair", `{"code":"`+next+`"}`)
		if status != 401 {
			t.Fatal("code accepted after three global attempts")
		}
		temporary := openClient(t, owner, false)
		var short struct {
			Token string `json:"token"`
			URL   string `json:"url"`
		}
		temporary.must(t, "session", nil, &short)
		status, _ = api(t, short.URL, short.Token, "GET", "/api/state", "")
		if status != 200 {
			t.Fatal("temporary token was never valid")
		}
		temporary.input.Close()
		wait(t, "token revoked on desktop disconnect", 5*time.Second, func() bool {
			status, _ := api(t, short.URL, short.Token, "GET", "/api/state", "")
			return status == 401
		})
	})
	c.must(t, "signin", nil, nil)
	wait(t, "routing on", 30*time.Second, func() bool { return getStatus(t, c).Routing == "on" })
	first := getStatus(t, c)
	t.Run("engine-ipc-rejects-standard-users", func(t *testing.T) {
		exe, _ := os.Executable()
		for _, user := range []actor{owner, other} {
			if b, err := user.command(exe, "client", "engine-denied").CombinedOutput(); err != nil {
				t.Fatal(err, string(b))
			}
		}
	})
	t.Run("adapter-carries-traffic", func(t *testing.T) {
		stream := proxyStream(t, session.URL, session.Token, echo)
		defer stream.Close()
		checkEcho(t, stream)
	})
	t.Run("owner-sees-another-users-app", func(t *testing.T) {
		status, b := api(t, session.URL, session.Token, "GET", "/api/state", "")
		if status != 200 {
			t.Fatal(status)
		}
		var state struct {
			Routing struct {
				Port int `json:"proxyPort"`
			} `json:"routing"`
		}
		if err := json.Unmarshal(b, &state); err != nil || state.Routing.Port == 0 {
			t.Fatal("proxy not ready", err)
		}
		path := filepath.Join(dir, binary("lifecycle-other-app"))
		process := other.command(path, fmt.Sprintf("127.0.0.1:%d", state.Routing.Port), echo)
		input, err := process.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		output, err := process.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		var diagnostics bytes.Buffer
		process.Stderr = &diagnostics
		if err := process.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { input.Close(); _ = process.Process.Kill(); _ = process.Wait() })
		line, err := bufio.NewReader(output).ReadString('\n')
		if err != nil || strings.TrimSpace(line) != "ready" {
			t.Fatal("other user's traffic did not start", err, diagnostics.String())
		}
		var observed []string
		defer func() {
			if t.Failed() {
				t.Logf("expected other-user executable %q; observed app paths: %q", path, observed)
			}
		}()
		wait(t, "other user's executable appears in owner view", 15*time.Second, func() bool {
			status, b := api(t, session.URL, session.Token, "GET", "/api/state", "")
			if status != 200 {
				return false
			}
			var state struct {
				Apps []struct {
					Path string `json:"path"`
				} `json:"apps"`
			}
			if json.Unmarshal(b, &state) != nil {
				return false
			}
			observed = nil
			for _, app := range state.Apps {
				observed = append(observed, app.Path)
				if strings.EqualFold(app.Path, path) {
					return true
				}
			}
			return false
		})
	})
	t.Run("service-isolation-and-hung-workers", func(t *testing.T) {
		control, err := service.Query(service.Control)
		if err != nil {
			t.Fatal(err)
		}
		engine, err := service.Query(service.Engine)
		if err != nil {
			t.Fatal(err)
		}
		assertServiceIsolation(t, control.PID, engine.PID)
		refs := runningWorkers(t, control.PID, dir)
		stream := proxyStream(t, session.URL, session.Token, echo)
		defer stream.Close()
		checkEcho(t, stream)
		for _, ref := range refs {
			if err := ref.suspend(); err != nil {
				t.Fatal(err)
			}
		}
		workersGone(t, refs, 45*time.Second)
		replacements := runningWorkers(t, control.PID, dir)
		for _, replacement := range replacements {
			for _, old := range refs {
				if replacement.id() == old.id() {
					t.Fatal("worker identity did not change")
				}
			}
		}
		checkEcho(t, stream)
	})
	t.Run("desktop-death-keeps-routing", func(t *testing.T) {
		desktop := owner.command(filepath.Join(dir, binary("netswitch-desktop")), "--background")
		if err := desktop.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = desktop.Process.Kill(); _ = desktop.Wait() })
		wait(t, "owner desktop attached", 20*time.Second, func() bool { return getStatus(t, c).DesktopPID == uint32(desktop.Process.Pid) })
		status, b := api(t, session.URL, session.Token, "GET", "/api/installed-apps", "")
		if status != 200 {
			t.Fatal("owner-session app listing failed", status, string(b))
		}
		var apps []any
		if err := json.Unmarshal(b, &apps); err != nil {
			t.Fatal("desktop did not return an app list", err)
		}
		if err := desktop.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		_ = desktop.Wait()
		if s := getStatus(t, c); s.Routing != "on" || s.Instance != first.Instance {
			t.Fatal("desktop death changed engine", s)
		}
	})
	t.Run("control-crash-reattaches", func(t *testing.T) {
		stream := proxyStream(t, session.URL, session.Token, echo)
		defer stream.Close()
		checkEcho(t, stream)
		old, err := service.Query(service.Control)
		if err != nil {
			t.Fatal(err)
		}
		workers := runningWorkers(t, old.PID, dir)
		engine, err := service.Query(service.Engine)
		if err != nil {
			t.Fatal(err)
		}
		kill(t, old.PID)
		workersGone(t, workers, 10*time.Second)
		checkEcho(t, stream)
		wait(t, "SCM/systemd Control recovery", 25*time.Second, func() bool {
			s, err := service.Query(service.Control)
			return err == nil && s.Running && s.PID != old.PID
		})
		c = openClient(t, owner, false)
		c.must(t, "session", nil, &session)
		wait(t, "engine reattach", 10*time.Second, func() bool { return getStatus(t, c).Routing == "on" })
		s := getStatus(t, c)
		engineAfter, err := service.Query(service.Engine)
		if err != nil || s.Instance != first.Instance || engineAfter.PID != engine.PID {
			t.Fatal("Control restart replaced engine", s, err)
		}
		checkEcho(t, stream)
	})
	t.Run("stale-controller-fenced", func(t *testing.T) { engineProbe(t, dir, data, "fence") })
	wait(t, "Control reattaches after fencing", 15*time.Second, func() bool { return getStatus(t, c).Routing == "on" })
	for _, point := range []string{"control-after-desired-commit", "control-after-apply-ack", "engine-after-apply-commit"} {
		t.Run(point, func(t *testing.T) {
			c = durableCrash(t, data, point, session.URL, session.Token, echo, owner)
			c.must(t, "session", nil, &session)
		})
	}
	t.Run("closure-replay-keeps-newer-flows", func(t *testing.T) {
		c = replayClosure(t, data, session.URL, session.Token, echo, owner)
		c.must(t, "session", nil, &session)
	})
	t.Run("engine-crash-recovers", func(t *testing.T) {
		stream := proxyStream(t, session.URL, session.Token, echo)
		defer stream.Close()
		checkEcho(t, stream)
		engine, err := service.Query(service.Engine)
		if err != nil {
			t.Fatal(err)
		}
		before := getStatus(t, c)
		kill(t, engine.PID)
		expectClosed(t, stream)
		directEcho(t, echo)
		wait(t, "new engine instance", 40*time.Second, func() bool { s := getStatus(t, c); return s.Routing == "on" && s.Instance != before.Instance })
	})
	t.Run("adapter-child-crash-gets-a-new-service-instance", func(t *testing.T) {
		engine, err := service.Query(service.Engine)
		if err != nil {
			t.Fatal(err)
		}
		connection, err := localipc.Dial(ctx, localipc.Endpoint{Path: localipc.DefaultPath("engine"), Kind: "engine", Service: service.Engine})
		if err != nil {
			t.Fatal(err)
		}
		rpc := lifecycle.NewRPC(connection)
		var hello struct {
			Snapshot struct {
				PID uint32 `json:"PID"`
			} `json:"adapterSnapshot"`
		}
		if err := rpc.Call(ctx, map[string]any{"method": "hello"}, &hello); err != nil {
			rpc.Close()
			t.Fatal(err)
		}
		rpc.Close()
		if hello.Snapshot.PID == 0 || hello.Snapshot.PID == engine.PID {
			t.Fatal("adapter child identity is not distinct")
		}
		before := getStatus(t, c).Instance
		stream := proxyStream(t, session.URL, session.Token, echo)
		defer stream.Close()
		checkEcho(t, stream)
		kill(t, hello.Snapshot.PID)
		expectClosed(t, stream)
		wait(t, "adapter crash changes the engine lifetime", 40*time.Second, func() bool { return getStatus(t, c).Routing == "on" && getStatus(t, c).Instance != before })
		after, err := service.Query(service.Engine)
		if err != nil || after.PID == engine.PID {
			t.Fatal("adapter restarted inside the old service lifetime", err)
		}
	})
	t.Run("explicit-stop-acknowledged", func(t *testing.T) {
		c.must(t, "routing", map[string]any{"on": false}, nil)
		wait(t, "engine service stopped", 10*time.Second, func() bool { s, err := service.Query(service.Engine); return err == nil && !s.Running })
		if getStatus(t, c).Routing != "off" {
			t.Fatal("off was not published")
		}
		c.must(t, "routing", map[string]any{"on": true}, nil)
		wait(t, "restart after explicit stop", 30*time.Second, func() bool { return getStatus(t, c).Routing == "on" })
	})
	t.Run("committed-stop-survives-control-crash", func(t *testing.T) {
		stream := proxyStream(t, session.URL, session.Token, echo)
		defer stream.Close()
		checkEcho(t, stream)
		arm(t, data, "control-after-stop-intent")
		pending := actionAsync(session.URL, session.Token, "api/routing", `{"on":false}`)
		pid := barrier(t, data, "control-after-stop-intent")
		var journal struct {
			Wanted bool `json:"wanted"`
		}
		if err := lifecycle.Read(filepath.Join(data, "control-journal.json"), &journal); err != nil || journal.Wanted {
			t.Fatal("stop intent was not durable", err)
		}
		checkEcho(t, stream)
		kill(t, pid)
		select {
		case err := <-pending:
			if err == nil {
				t.Fatal("stop was acknowledged before engine cleanup")
			}
		case <-time.After(40 * time.Second):
			t.Fatal("interrupted stop request hung")
		}
		wait(t, "Control restores committed stop", 25*time.Second, func() bool { s, err := service.Query(service.Control); return err == nil && s.Running && s.PID != pid })
		c = openClient(t, owner, false)
		c.must(t, "session", nil, &session)
		if getStatus(t, c).Routing != "off" {
			t.Fatal("restart reversed the saved stop")
		}
		expectClosed(t, stream)
		wait(t, "stopped engine service", 10*time.Second, func() bool { s, err := service.Query(service.Engine); return err == nil && !s.Running })
		c.must(t, "routing", map[string]any{"on": true}, nil)
		wait(t, "owner starts routing again", 30*time.Second, func() bool { return getStatus(t, c).Routing == "on" })
	})
	t.Run("five-failures-stay-stopped-across-control-restart", func(t *testing.T) {
		c.must(t, "routing", map[string]any{"on": true}, nil) // explicit Retry resets the budget
		for i := 0; i < 5; i++ {
			engine, err := service.Query(service.Engine)
			if err != nil || !engine.Running {
				t.Fatal("crash precondition", engine, err)
			}
			before := getStatus(t, c).Instance
			kill(t, engine.PID)
			if i < 4 {
				wait(t, "bounded engine retry", 45*time.Second, func() bool { s := getStatus(t, c); return s.Routing == "on" && s.Instance != before })
			}
		}
		wait(t, "durable crash-loop latch", 15*time.Second, func() bool {
			var journal struct {
				Failures []int64 `json:"failures"`
			}
			return lifecycle.Read(filepath.Join(data, "control-journal.json"), &journal) == nil && len(journal.Failures) >= 5
		})
		control, err := service.Query(service.Control)
		if err != nil {
			t.Fatal(err)
		}
		kill(t, control.PID)
		wait(t, "Control recovers with retry budget", 25*time.Second, func() bool {
			s, err := service.Query(service.Control)
			return err == nil && s.Running && s.PID != control.PID
		})
		c = openClient(t, owner, false)
		c.must(t, "session", nil, &session)
		deadline := time.Now().Add(32 * time.Second)
		for time.Now().Before(deadline) {
			engine, err := service.Query(service.Engine)
			if err != nil || engine.Running {
				t.Fatal("crash loop restarted after its fifth failure", engine, err)
			}
			time.Sleep(time.Second)
		}
		s := getStatus(t, c)
		if s.Routing != "error" || s.Error == nil || !strings.Contains(*s.Error, "retry") {
			t.Fatal("crash-loop error is not actionable", s)
		}
		c.must(t, "routing", map[string]any{"on": true}, nil)
		wait(t, "owner Retry releases latch", 30*time.Second, func() bool { return getStatus(t, c).Routing == "on" })
	})
	t.Run("blocked-apply-cannot-hold-the-lease", func(t *testing.T) {
		stream := proxyStream(t, session.URL, session.Token, echo)
		defer stream.Close()
		checkEcho(t, stream)
		arm(t, data, "engine-after-apply-commit")
		pending := mutateAsync(session.URL, session.Token, "Lease expiry")
		enginePID := barrier(t, data, "engine-after-apply-commit")
		restore := disableRecovery(t)
		control, err := service.Query(service.Control)
		if err != nil {
			t.Fatal(err)
		}
		kill(t, control.PID)
		checkEcho(t, stream)
		select {
		case <-pending:
		case <-time.After(40 * time.Second):
			t.Fatal("interrupted apply did not release HTTP")
		}
		wait(t, "lease stops a blocked engine command", 50*time.Second, func() bool { s, err := service.Query(service.Engine); return err == nil && !s.Running })
		expectClosed(t, stream)
		directEcho(t, echo)
		restore()
		if err := service.Start(ctx, service.Control); err != nil {
			t.Fatal(err)
		}
		c = openClient(t, owner, false)
		c.must(t, "session", nil, &session)
		wait(t, "fresh engine after expiry", 35*time.Second, func() bool {
			s, err := service.Query(service.Engine)
			return err == nil && s.Running && s.PID != enginePID && getStatus(t, c).Routing == "on"
		})
	})
	t.Run("lease-lapse-fails-open", func(t *testing.T) {
		stream := proxyStream(t, session.URL, session.Token, echo)
		defer stream.Close()
		checkEcho(t, stream)
		restore := disableRecovery(t)
		defer restore()
		control, err := service.Query(service.Control)
		if err != nil {
			t.Fatal(err)
		}
		engine, err := service.Query(service.Engine)
		if err != nil {
			t.Fatal(err)
		}
		kill(t, control.PID)
		time.Sleep(2 * time.Second)
		still, err := service.Query(service.Engine)
		if err != nil || still.PID != engine.PID || !still.Running {
			t.Fatal("engine died immediately with Control", err)
		}
		checkEcho(t, stream)
		wait(t, "30-second lease cleanup", 40*time.Second, func() bool { s, err := service.Query(service.Engine); return err == nil && !s.Running })
		expectClosed(t, stream)
		directEcho(t, echo)
	})
	t.Run("reboot-like-restart-waits-for-sign-in", func(t *testing.T) {
		// Model a new boot while keeping both durable journals, rather than
		// confusing an ordinary same-boot Control recovery with a reboot.
		var journal map[string]any
		if err := lifecycle.Read(filepath.Join(data, "control-journal.json"), &journal); err != nil {
			t.Fatal(err)
		}
		journal["bootId"] = "previous-boot"
		if err := lifecycle.Save(filepath.Join(data, "control-journal.json"), journal); err != nil {
			t.Fatal(err)
		}
		if err := service.Start(ctx, service.Control); err != nil {
			t.Fatal(err)
		}
		c = openClient(t, owner, false)
		if getStatus(t, c).Routing != "off" {
			t.Fatal("routing started without sign-in")
		}
		c.must(t, "signin", nil, nil)
		wait(t, "sign-in restores routing", 30*time.Second, func() bool { return getStatus(t, c).Routing == "on" })
	})
	t.Run("clean-service-stop", func(t *testing.T) {
		if err := service.Stop(ctx, service.Control); err != nil {
			t.Fatal(err)
		}
		wait(t, "clean engine exit", 10*time.Second, func() bool { s, err := service.Query(service.Engine); return err == nil && !s.Running })
	})
}
func binary(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}
func kill(t *testing.T, pid uint32) {
	t.Helper()
	if pid == 0 {
		t.Fatal("refusing to kill PID 0")
	}
	p, err := os.FindProcess(int(pid))
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Kill(); err != nil {
		t.Fatal(err)
	}
}
func probe(ctx context.Context, issued *uint64) error {
	endpoint := localipc.Endpoint{Path: localipc.DefaultPath("engine"), Kind: "engine", Service: service.Engine}
	c, err := localipc.Dial(ctx, endpoint)
	if err != nil {
		return err
	}
	rpc := lifecycle.NewRPC(c)
	defer rpc.Close()
	var hello struct {
		Instance string `json:"engineInstanceId"`
	}
	if err = rpc.Call(ctx, map[string]any{"method": "hello"}, &hello); err != nil {
		return err
	}
	var first, second struct {
		Epoch uint64 `json:"epoch"`
	}
	for _, out := range []any{&first, &second} {
		if err = rpc.Call(ctx, map[string]any{"method": "attach", "engineInstanceId": hello.Instance}, out); err != nil {
			return err
		}
	}
	if second.Epoch != first.Epoch+1 {
		return fmt.Errorf("engine did not issue consecutive epochs")
	}
	*issued = second.Epoch
	for _, method := range []string{"renew", "start", "apply", "stop", "closeFlows"} {
		if err = rpc.Call(ctx, map[string]any{"method": method, "engineInstanceId": hello.Instance, "epoch": first.Epoch}, nil); err == nil {
			return fmt.Errorf("stale %s accepted", method)
		}
	}
	if err = rpc.Call(ctx, map[string]any{"method": "renew", "engineInstanceId": "wrong-instance", "epoch": second.Epoch}, nil); err == nil {
		return fmt.Errorf("wrong instance accepted")
	}
	return rpc.Call(ctx, map[string]any{"method": "renew", "engineInstanceId": hello.Instance, "epoch": second.Epoch}, nil)
}
func engineProbe(t *testing.T, _, data, _ string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	engine, err := service.Query(service.Engine)
	if err != nil {
		t.Fatal(err)
	}
	var epoch uint64
	if err := probe(ctx, &epoch); err != nil {
		t.Fatal(err)
	}
	wait(t, "Control acquired a fresh engine epoch", 20*time.Second, func() bool {
		var state struct {
			Epoch uint64 `json:"epoch"`
		}
		return lifecycle.Read(filepath.Join(data, "engine-state.json"), &state) == nil && state.Epoch > epoch
	})
	after, err := service.Query(service.Engine)
	if err != nil || after.PID != engine.PID {
		t.Fatal("fencing replaced the engine", err)
	}
}
