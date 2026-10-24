// These tests install real services and kill processes. They are deliberately
// gated to disposable hosted runners, never a developer's live router.
package lifecycle_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
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
	if len(args) > 0 && args[0] == "admission-flood" {
		if err := idleAdmissionFlood(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	if len(args) == 2 && args[0] == "http-flood" {
		if err := httpFlood(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	if len(args) == 2 && args[0] == "http-churn" {
		if err := httpChurn(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	if len(args) == 3 && args[0] == "http-latency" {
		if err := httpLatency(args[1], args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	if len(args) == 1 && args[0] == "medium-pipe-read" {
		if err := mediumPipeRead(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	if len(args) == 1 && args[0] == "low-pipe" {
		if err := lowPipeClient(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	if len(args) == 2 && args[0] == "held-store" {
		if err := heldStoreClient(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	if len(args) > 0 && args[0] == "legacy-mutex" {
		if err := legacyMutex(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	if len(args) > 0 && args[0] == "http" {
		return httpClientMain()
	}
	if len(args) > 0 && args[0] == "disconnect-burst" {
		if err := disconnectBurst(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	if len(args) > 0 && args[0] == "status-capacity" {
		if err := statusCapacity(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
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
	ctx, cancel := context.WithTimeout(context.Background(), 14*time.Minute)
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
	EarlyDisconnects uint64  `json:"earlyDisconnects"`
	Routing          string  `json:"routing"`
	Instance         string  `json:"engineInstanceId"`
	ControlPID       uint32  `json:"controlPID"`
	DesktopPID       uint32  `json:"desktopPID"`
	Error            *string `json:"error"`
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
	response, err := apiClient(20 * time.Second).Do(r)
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
	realWTSOwner := ""
	if runtime.GOOS == "windows" {
		if err := lifecycle.Save(filepath.Join(data, "fault-owner-sessions.json"), map[string]bool{owner.id(): true, other.id(): true}); err != nil {
			t.Fatal(err)
		}
		t.Log("synthetic Windows actors use injected WTS presence; their IPC authentication still uses real OS tokens")
		t.Run("real-WTS-session-probe", func(t *testing.T) {
			probe := exec.Command(filepath.Join(dir, "session.test.exe"), "-test.v", "-test.run=^TestRealWindowsOwnerSession$")
			probe.Env = append(os.Environ(), "NETSWITCH_REAL_WTS_PROBE=1")
			b, err := probe.CombinedOutput()
			if err != nil {
				t.Fatal(err, string(b))
			}
			t.Log(string(b))
			if strings.Contains(string(b), "hosted runner has no real signed-in WTS user") {
				t.Skip("runner has no real WTS user; actual-service probe unavailable")
			}
			if !strings.Contains(string(b), "--- PASS: TestRealWindowsOwnerSession") {
				t.Fatal("real WTS probe did not run and pass")
			}
			for _, field := range strings.Fields(string(b)) {
				if strings.HasPrefix(field, "REAL_WTS_OWNER=") {
					realWTSOwner = strings.TrimPrefix(field, "REAL_WTS_OWNER=")
				}
			}
			if realWTSOwner == "" {
				t.Fatal("real WTS probe returned no owner SID")
			}
		})
		// The installed Control queries real WTS for these users under its
		// own service token. The other actor has a real logon but no WTS
		// session, so it is the "signed out" case and needs no runner user.
		probed := []string{other.id()}
		if realWTSOwner != "" {
			probed = append(probed, realWTSOwner)
		}
		if err := lifecycle.Save(filepath.Join(data, "fault-real-session.json"), probed); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("held-hostile-store-cannot-block-install", func(t *testing.T) { blockedStoreInstallation(t, dir, "", other) })
	t.Run("installation-rejects-writable-images-and-parents", func(t *testing.T) { installationTrust(t, dir) })
	// The product build runs the native engine over a real TUN: TestISP on
	// Windows, the namespace fixture on Linux. Every traffic check below goes
	// through that capture, and fail-open checks use the same target directly.
	config := lifecycle.Config{Directory: dir, Data: data, Mode: "tun"}
	if err := lifecycle.Save(filepath.Join(data, "service-config.json"), config); err != nil {
		t.Fatal(err)
	}
	fixture := prepareTUN(t, dir, data)
	nic, _ := primaryInterface(t)
	if err := lifecycle.Save(filepath.Join(data, "settings.json"), map[string]any{"lines": []lines.Line{{ID: "a1", Alias: fixture.line, Label: "Test line", Weight: 1}}, "ipv6": "off", "checkForUpdates": false}); err != nil {
		t.Fatal(err)
	}
	if err := service.Install(service.Config{Directory: dir, Data: data, Native: true}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 38*time.Minute)
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
	if runtime.GOOS == "windows" {
		t.Run("real-WTS-query-inside-Control", func(t *testing.T) {
			var result struct {
				PID     uint32 `json:"pid"`
				Results []struct {
					Owner   string `json:"owner"`
					Present bool   `json:"present"`
					Error   string `json:"error"`
				} `json:"results"`
				Sessions string `json:"sessions"`
			}
			wait(t, "real WTS result from installed Control", 10*time.Second, func() bool {
				b, err := os.ReadFile(filepath.Join(data, "fault-real-session-result.json"))
				return err == nil && json.Unmarshal(b, &result) == nil
			})
			t.Logf("REAL_WTS_SESSIONS %s", result.Sessions)
			status, err := service.Query(service.Control)
			if err != nil || result.PID != status.PID {
				t.Fatalf("real WTS probe did not come from the installed Control: result=%+v service=%+v error=%v", result, status, err)
			}
			checked := map[string]bool{}
			for _, r := range result.Results {
				switch r.Owner {
				case other.id():
					// Every session kind on the runner must resolve; an
					// error here means sign-out would never clear routing.
					if r.Present || r.Error != "" {
						t.Fatalf("signed-out user was not cleanly absent: %+v; sessions: %s", r, result.Sessions)
					}
					t.Logf("REAL_WTS_ABSENT pid=%d user=%s present=false error=none", result.PID, r.Owner)
				case realWTSOwner:
					if !r.Present || r.Error != "" {
						t.Fatalf("signed-in user was not present: %+v; sessions: %s", r, result.Sessions)
					}
					t.Logf("REAL_WTS_SERVICE pid=%d owner=%s present=true", result.PID, r.Owner)
				default:
					t.Fatalf("unexpected probe result %+v", r)
				}
				checked[r.Owner] = true
			}
			if !checked[other.id()] || realWTSOwner != "" && !checked[realWTSOwner] {
				t.Fatalf("probe results incomplete: %+v", result)
			}
		})
	}
	t.Run("pending-enrollment-and-sign-in", func(t *testing.T) {
		readonly := openClient(t, other, true)
		defer readonly.input.Close()
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
	t.Run("desktop-retries-unavailable-control-at-signin", func(t *testing.T) { desktopStartupRetry(t, config, owner) })
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
		defer readonly.input.Close()
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
		exe, _ := os.Executable()
		attack := other.command(exe, "client", "status-capacity")
		input, err := attack.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		attackOutput, err := attack.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		var diagnostics bytes.Buffer
		attack.Stderr = &diagnostics
		if err := attack.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { input.Close(); _ = attack.Process.Kill(); _ = attack.Wait() }()
		ready, err := bufio.NewReader(attackOutput).ReadString('\n')
		if err != nil || !strings.HasPrefix(ready, "holding 40 ") {
			t.Fatal("capacity precondition", ready, err, diagnostics.String())
		}
		fresh := openClient(t, owner, false)
		fresh.must(t, "desktop-connect", nil, nil)
		fresh.must(t, "session", nil, &session)
		if code, _ := apiAs(t, owner, session.URL, session.Token, "GET", "/api/state", ""); code != 200 {
			t.Fatal("owner token blocked during attack", code)
		}
		if b, err := owner.command(filepath.Join(dir, binary("netswitchctl")), "status").CombinedOutput(); err != nil {
			t.Fatal("owner CLI blocked during attack", err, string(b))
		}
		t.Log("owner desktop, token and CLI succeeded while all 40 attacker handles remained open")
	})
	t.Run("pairing-and-bearer", func(t *testing.T) {
		var code string
		c.must(t, "pair", nil, &code)
		status, _ := api(t, session.URL, "", "GET", "/api/state", "")
		if status != 401 {
			t.Fatal("anonymous API accepted", status)
		}
		for range 5 {
			status, _ := apiAs(t, other, session.URL, "", "POST", "/api/pair", `{"code":"000000"}`)
			if status != 403 {
				t.Fatal("other user reached pairing attempts", status)
			}
		}
		status, b := apiAs(t, owner, session.URL, "", "POST", "/api/pair", `{"code":"`+code+`"}`)
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
		status, _ = apiAs(t, owner, session.URL, "", "POST", "/api/pair", `{"code":"`+code+`"}`)
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
			status, _ = apiAs(t, owner, session.URL, "", "POST", "/api/pair", `{"code":"`+wrong+`"}`)
			if status != 401 {
				t.Fatal("wrong code accepted")
			}
		}
		status, _ = apiAs(t, owner, session.URL, "", "POST", "/api/pair", `{"code":"`+next+`"}`)
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
	if runtime.GOOS == "windows" {
		t.Run("system-pipe-accept-race", func(t *testing.T) {
			b, err := exec.Command(filepath.Join(dir, "ipc.test.exe"), "-test.v", "-test.run=^(TestClientClosesBeforePipeAccept|TestPipeIdentityUsesEffectiveClientToken)$", "-test.count=1").CombinedOutput()
			if err != nil || !strings.Contains(string(b), "--- PASS: TestClientClosesBeforePipeAccept") {
				t.Fatal("SYSTEM pipe regression did not pass", err, string(b))
			}
			if realWTSOwner != "" && !strings.Contains(string(b), "--- PASS: TestPipeIdentityUsesEffectiveClientToken") {
				t.Fatal("effective-token identity probe did not run despite a real WTS session", string(b))
			}
			t.Log(string(b))
		})
	}
	t.Run("non-owner-connect-close-preserves-routing", func(t *testing.T) {
		initialClosed := getStatus(t, c).EarlyDisconnects
		exe, _ := os.Executable()
		attack := other.command(exe, "client", "disconnect-burst")
		var output bytes.Buffer
		attack.Stdout = &output
		attack.Stderr = &output
		if err := attack.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- attack.Wait() }()
		time.Sleep(250 * time.Millisecond)
		fresh := openClient(t, owner, false)
		fresh.must(t, "session", nil, nil)
		fresh.input.Close()
		select {
		case err := <-done:
			t.Fatal("flood ended before owner admission was proved", err)
		default:
		}
		if err := <-done; err != nil {
			t.Fatal(err, output.String())
		}
		t.Log(output.String())
		if getStatus(t, c).Routing != "on" {
			t.Fatal("routing lost during active connection flood")
		}
		after := getStatus(t, c)
		if runtime.GOOS == "windows" && after.EarlyDisconnects <= initialClosed {
			t.Fatal("raw burst never exercised ERROR_NO_DATA")
		}
		t.Logf("closed-before-accept count=%d", after.EarlyDisconnects)
		if after.Routing != "on" || after.ControlPID != first.ControlPID || after.Instance != first.Instance {
			t.Fatal("connect-close changed routing or service lifetime", after)
		}
	})
	t.Run("low-integrity-owner-cannot-exhaust-owner-slots", func(t *testing.T) { lowIntegrityCapacity(t, owner) })
	t.Run("low-integrity-owner-cannot-pair-over-HTTP", func(t *testing.T) { lowIntegrityPairing(t, c, owner) })
	t.Run("HTTP-flood-preserves-owner-capacity", func(t *testing.T) { httpCapacity(t, c, owner, other) })
	t.Run("HTTP-churn-keeps-owner-latency", func(t *testing.T) { httpChurnLatency(t, c, owner, other) })
	t.Run("idle-open-flood-preserves-owner-admission", func(t *testing.T) { idleAdmissionCapacity(t, dir, data, owner, other) })
	t.Run("last-logind-session-stops-routing", func(t *testing.T) { ownerSignout(t, c, owner) })
	t.Run("engine-ipc-rejects-standard-users", func(t *testing.T) {
		exe, _ := os.Executable()
		for _, user := range []actor{owner, other} {
			if b, err := user.command(exe, "client", "engine-denied").CombinedOutput(); err != nil {
				t.Fatal(err, string(b))
			}
		}
	})
	t.Run("engine-carries-traffic", func(t *testing.T) {
		stream := routedStream(t, ctx, fixture)
		defer stream.Close()
		fixture.exchange(t, stream)
		assertTUNCaptured(t, session.URL, session.Token, fixture)
	})
	t.Run("owner-sees-another-users-app", func(t *testing.T) {
		path := filepath.Join(dir, binary("lifecycle-other-app"))
		process := other.command(path, fixture.target)
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
		stream := routedStream(t, ctx, fixture)
		defer stream.Close()
		fixture.exchange(t, stream)
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
		fixture.exchange(t, stream)
	})
	t.Run("desktop-death-keeps-routing", func(t *testing.T) {
		before := getStatus(t, c)
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
		if s := getStatus(t, c); s.Routing != "on" || s.Instance != before.Instance {
			t.Fatal("desktop death changed engine", s)
		}
	})
	t.Run("control-crash-reattaches", func(t *testing.T) {
		before := getStatus(t, c)
		stream := routedStream(t, ctx, fixture)
		defer stream.Close()
		fixture.exchange(t, stream)
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
		fixture.exchange(t, stream)
		wait(t, "SCM/systemd Control recovery", 25*time.Second, func() bool {
			s, err := service.Query(service.Control)
			return err == nil && s.Running && s.PID != old.PID
		})
		c = openClient(t, owner, false)
		c.must(t, "session", nil, &session)
		wait(t, "engine reattach", 10*time.Second, func() bool { return getStatus(t, c).Routing == "on" })
		s := getStatus(t, c)
		engineAfter, err := service.Query(service.Engine)
		if err != nil || s.Instance != before.Instance || engineAfter.PID != engine.PID {
			t.Fatal("Control restart replaced engine", s, err)
		}
		fixture.exchange(t, stream)
	})
	t.Run("stale-controller-fenced", func(t *testing.T) { engineProbe(t, dir, data, "fence") })
	wait(t, "Control reattaches after fencing", 15*time.Second, func() bool { return getStatus(t, c).Routing == "on" })
	for _, point := range []string{"control-after-desired-commit", "control-after-apply-ack", "engine-after-apply-commit"} {
		t.Run(point, func(t *testing.T) {
			c = durableCrash(t, ctx, data, point, session.URL, session.Token, fixture, owner)
			c.must(t, "session", nil, &session)
		})
	}
	t.Run("closure-replay-keeps-newer-flows", func(t *testing.T) {
		c = replayClosure(t, ctx, data, fixture, owner)
		c.must(t, "session", nil, &session)
	})
	t.Run("engine-crash-recovers", func(t *testing.T) {
		stream := routedStream(t, ctx, fixture)
		defer stream.Close()
		fixture.exchange(t, stream)
		engine, err := service.Query(service.Engine)
		if err != nil {
			t.Fatal(err)
		}
		before := getStatus(t, c)
		kill(t, engine.PID)
		expectClosed(t, stream)
		directTraffic(t, ctx, fixture)
		wait(t, "new engine instance", 40*time.Second, func() bool { s := getStatus(t, c); return s.Routing == "on" && s.Instance != before.Instance })
	})
	t.Run("engine-child-crash-gets-a-new-service-instance", func(t *testing.T) {
		// The Engine service is the supervisor host; the forwarding engine is
		// its verified child (spec §3.4). The child's death ends the host's
		// lifetime, and Control starts a fresh service instance.
		engine, err := service.Query(service.Engine)
		if err != nil {
			t.Fatal(err)
		}
		before := getStatus(t, c).Instance
		child := nativeChildPID(t, data, before)
		if child == engine.PID {
			t.Fatal("engine child identity is not distinct from the host")
		}
		stream := routedStream(t, ctx, fixture)
		defer stream.Close()
		fixture.exchange(t, stream)
		kill(t, child)
		expectClosed(t, stream)
		wait(t, "child crash changes the engine lifetime", 40*time.Second, func() bool { return getStatus(t, c).Routing == "on" && getStatus(t, c).Instance != before })
		after, err := service.Query(service.Engine)
		if err != nil || after.PID == engine.PID {
			t.Fatal("engine restarted inside the old service lifetime", err)
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
	t.Run("binding-change-waits-for-old-service-exit", func(t *testing.T) {
		before := getStatus(t, c)
		second := fixture.churnLine // Linux's second physical path; Windows adds the runner's uplink
		if second == "" {
			second = nic
		}
		body, _ := json.Marshal(map[string]string{"alias": second})
		code, b := api(t, session.URL, session.Token, "POST", "/api/lines/add", string(body))
		if code != 200 {
			t.Fatal("add fixture binding", code, string(b))
		}
		wait(t, "new service after binding addition", 40*time.Second, func() bool { s := getStatus(t, c); return s.Routing == "on" && s.Instance != before.Instance })
		var state struct {
			Lines []lines.Line `json:"lines"`
		}
		if json.Unmarshal(b, &state) != nil || len(state.Lines) != 2 {
			t.Fatal("two-line precondition", string(b))
		}
		before = getStatus(t, c)
		body, _ = json.Marshal(map[string]string{"id": state.Lines[1].ID})
		code, b = api(t, session.URL, session.Token, "POST", "/api/lines/remove", string(body))
		if code != 200 {
			t.Fatal("remove fixture binding", code, string(b))
		}
		wait(t, "new service after binding removal", 40*time.Second, func() bool { s := getStatus(t, c); return s.Routing == "on" && s.Instance != before.Instance })
		stream := routedStream(t, ctx, fixture)
		defer stream.Close()
		fixture.exchange(t, stream)
		// The new instance retires every earlier instance's outcome record,
		// so only the live instance's result remains in the store.
		entries, err := os.ReadDir(data)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "engine-outcome-") {
				count++
			}
		}
		if count != 1 {
			t.Fatal("retired engine instances still present", count)
		}
	})
	t.Run("enrollment-preserves-routing-and-same-owner-is-noop", func(t *testing.T) {
		resetControlRecoveryWindow(t)
		before := getStatus(t, c)
		stream := routedStream(t, ctx, fixture)
		defer stream.Close()
		fixture.exchange(t, stream)
		ctl := filepath.Join(dir, binary("netswitchctl"))
		if b, err := exec.Command(ctl, "enroll", "--data", data, "--owner", owner.id()).CombinedOutput(); err != nil {
			t.Fatal(err, string(b))
		}
		if after := getStatus(t, c); after.ControlPID != before.ControlPID || after.Instance != before.Instance {
			t.Fatal("same owner enrollment restarted services", after)
		}
		if b, err := exec.Command(ctl, "enroll", "--data", data, "--owner", other.id()).CombinedOutput(); err != nil {
			t.Fatal(err, string(b))
		}
		fixture.exchange(t, stream)
		replacement := openClient(t, other, false)
		after := getStatus(t, replacement)
		if after.Instance != before.Instance || after.ControlPID == before.ControlPID || after.Routing != "on" {
			t.Fatal("Control replacement lost engine", after)
		}
		replacement.input.Close()
		if b, err := exec.Command(ctl, "enroll", "--data", data, "--owner", owner.id()).CombinedOutput(); err != nil {
			t.Fatal(err, string(b))
		}
		c = openClient(t, owner, false)
		c.must(t, "session", nil, &session)
		fixture.exchange(t, stream)
	})
	t.Run("legacy-global-mutex-cannot-block-start", func(t *testing.T) {
		if runtime.GOOS != "windows" {
			t.Skip("Windows kernel namespace attack")
		}
		c.must(t, "routing", map[string]any{"on": false}, nil)
		attack := other.command(hostedTestExecutable(), "client", "legacy-mutex")
		input, err := attack.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		output, err := attack.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		var diagnostic bytes.Buffer
		attack.Stderr = &diagnostic
		if err := attack.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { input.Close(); _ = attack.Process.Kill(); _ = attack.Wait() }()
		line, err := bufio.NewReader(output).ReadString('\n')
		if err != nil || strings.TrimSpace(line) != "held" {
			t.Fatal("mutex squatter precondition", line, err, diagnostic.String())
		}
		c.must(t, "routing", map[string]any{"on": true}, nil)
		if getStatus(t, c).Routing != "on" {
			t.Fatal("planted Global mutex blocked engine")
		}
	})
	t.Run("committed-stop-survives-control-crash", func(t *testing.T) {
		stream := routedStream(t, ctx, fixture)
		defer stream.Close()
		fixture.exchange(t, stream)
		arm(t, data, "control-after-stop-intent")
		pending := actionAsync(session.URL, session.Token, "api/routing", `{"on":false}`)
		pid := barrier(t, data, "control-after-stop-intent")
		var journal struct {
			Wanted bool `json:"wanted"`
		}
		if err := lifecycle.Read(filepath.Join(data, "control-journal.json"), &journal); err != nil || journal.Wanted {
			t.Fatal("stop intent was not durable", err)
		}
		fixture.exchange(t, stream)
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
	// These are independent fault cases, not prerequisites for each other.
	// Keep accumulated journals; only the explicit owner Retry resets its
	// budget. A failure must not lend a stale session or live service to the
	// next case, especially the reboot/sign-in safety proof.
	readyFaultCase := func(t *testing.T) {
		t.Helper()
		t.Cleanup(func() {
			if !t.Failed() {
				return
			}
			restore := disableRecovery(t)
			defer restore()
			for _, name := range []string{service.Control, service.Engine} {
				s, err := service.Query(name)
				t.Logf("FAILED_CASE_SERVICE name=%s status=%+v error=%v", name, s, err)
				if err == nil && s.Stopped {
					continue
				}
				stop, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				if err := service.ForceStop(stop, name); err != nil {
					t.Error("isolate failed case", name, err)
				}
				cancel()
			}
		})
		if err := service.Start(ctx, service.Control); err != nil {
			t.Fatal(err)
		}
		c = openClient(t, owner, false)
		c.must(t, "session", nil, &session)
		c.must(t, "routing", map[string]any{"on": true}, nil)
		wait(t, "independent fault-case routing", 35*time.Second, func() bool { return getStatus(t, c).Routing == "on" })
		stream := routedStream(t, ctx, fixture)
		defer stream.Close()
		fixture.exchange(t, stream)
	}
	t.Run("five-failures-stay-stopped-across-control-restart", func(t *testing.T) {
		readyFaultCase(t)
		for i := 0; i < 5; i++ {
			engine, err := service.Query(service.Engine)
			if err != nil || !engine.Running {
				t.Fatal("crash precondition", engine, err)
			}
			before := getStatus(t, c).Instance
			kill(t, engine.PID)
			if i < 4 {
				var last status
				t.Cleanup(func() {
					if t.Failed() {
						t.Logf("ENGINE_RETRY injected_crash=%d previous_instance=%s last_status=%+v", i+1, before, last)
					}
				})
				wait(t, "bounded engine retry", 45*time.Second, func() bool { last = getStatus(t, c); return last.Routing == "on" && last.Instance != before })
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
		// The native child stalls inside a durable revision write while
		// Control dies. Spec §2: a lapsed lease stops forwarding whatever a
		// command is doing, so the engine reports the stall as a failure
		// instead of waiting on the stuck command, and its host cleans up.
		readyFaultCase(t)
		stream := routedStream(t, ctx, fixture)
		defer stream.Close()
		fixture.exchange(t, stream)
		arm(t, data, "engine-after-apply-commit")
		pending := mutateAsync(session.URL, session.Token, "Lease expiry")
		enginePID := barrier(t, data, "engine-after-apply-commit")
		restore := disableRecovery(t)
		control, err := service.Query(service.Control)
		if err != nil {
			t.Fatal(err)
		}
		kill(t, control.PID)
		fixture.exchange(t, stream)
		select {
		case <-pending:
		case <-time.After(40 * time.Second):
			t.Fatal("interrupted apply did not release HTTP")
		}
		wait(t, "lease stops a blocked engine command", 50*time.Second, func() bool { s, err := service.Query(service.Engine); return err == nil && !s.Running })
		expectClosed(t, stream)
		directTraffic(t, ctx, fixture)
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
		readyFaultCase(t)
		stream := routedStream(t, ctx, fixture)
		defer stream.Close()
		fixture.exchange(t, stream)
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
		fixture.exchange(t, stream)
		wait(t, "30-second lease cleanup", 40*time.Second, func() bool { s, err := service.Query(service.Engine); return err == nil && !s.Running })
		expectClosed(t, stream)
		directTraffic(t, ctx, fixture)
	})
	t.Run("reboot-like-restart-waits-for-sign-in", func(t *testing.T) {
		readyFaultCase(t)
		old, err := service.Query(service.Control)
		if err != nil || !old.Running {
			t.Fatal("reboot precondition: Control", old, err)
		}
		restore := disableRecovery(t)
		kill(t, old.PID) // preserve durable routing intent, unlike a clean stop
		wait(t, "old Control is gone before boot edit", 10*time.Second, func() bool { s, e := service.Query(service.Control); return e == nil && s.Stopped })
		if err := service.Stop(ctx, service.Engine); err != nil {
			t.Fatal(err)
		}
		wait(t, "old engine is gone before boot edit", 10*time.Second, func() bool { s, e := service.Query(service.Engine); return e == nil && s.Stopped })
		// Model a new boot while keeping both durable journals, rather than
		// confusing an ordinary same-boot Control recovery with a reboot.
		var journal map[string]any
		if err := lifecycle.Read(filepath.Join(data, "control-journal.json"), &journal); err != nil {
			t.Fatal(err)
		}
		if journal["wanted"] != true {
			t.Fatal("reboot proof needs saved routing-on intent", journal["wanted"])
		}
		journal["bootId"] = "previous-boot"
		if err := lifecycle.Save(filepath.Join(data, "control-journal.json"), journal); err != nil {
			t.Fatal(err)
		}
		restore()
		if err := service.Start(ctx, service.Control); err != nil {
			t.Fatal(err)
		}
		c = openClient(t, owner, false)
		fresh := getStatus(t, c)
		engine, err := service.Query(service.Engine)
		if fresh.ControlPID == old.PID || fresh.Routing != "off" || err != nil || !engine.Stopped {
			t.Fatal("new-boot sign-in gate: expected new Control off and engine stopped", fresh, engine, err)
		}
		// Cross several automatic-recovery ticks before authorizing sign-in.
		// A single immediate snapshot could race an unintended delayed start.
		for until := time.Now().Add(5 * time.Second); time.Now().Before(until); {
			current := getStatus(t, c)
			engine, err = service.Query(service.Engine)
			if current.ControlPID != fresh.ControlPID || current.Routing != "off" || err != nil || !engine.Stopped {
				t.Fatal("routing changed before explicit sign-in", current, engine, err)
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Logf("REBOOT_SIGNIN_GATE old_control=%d new_control=%d wanted_before_boot=true routing=%s engine_stopped=%t observed_off_for=5s", old.PID, fresh.ControlPID, fresh.Routing, engine.Stopped)
		c.must(t, "signin", nil, nil)
		wait(t, "sign-in restores routing", 30*time.Second, func() bool { return getStatus(t, c).Routing == "on" })
	})
	t.Run("clean-service-stop", func(t *testing.T) {
		began := time.Now()
		defer func() { t.Logf("LIFECYCLE_CLEAN_STOP elapsed=%s", time.Since(began)) }()
		if err := service.Stop(ctx, service.Control); err != nil {
			t.Fatal(err)
		}
		wait(t, "clean engine exit", 10*time.Second, func() bool { s, err := service.Query(service.Engine); return err == nil && !s.Running })
	})
	t.Run("acknowledged-stop-forces-stuck-service-exit", func(t *testing.T) {
		if err := service.Start(ctx, service.Control); err != nil {
			t.Fatal(err)
		}
		c := openClient(t, owner, false)
		defer c.input.Close()
		c.must(t, "routing", map[string]any{"on": true}, nil)
		wait(t, "routing before bounded stop", 30*time.Second, func() bool { return getStatus(t, c).Routing == "on" })
		// The child acknowledges the stop and cleans up, then refuses to exit.
		// Its host's bounded stop and Control's own forced stop both end the
		// service inside the same window; neither may wait on the stuck child.
		instance := getStatus(t, c).Instance
		arm(t, data, "engine-after-stop-cleanup")
		started := time.Now()
		finished := make(chan error, 1)
		go func() { _, err := c.call(t, "routing", map[string]any{"on": false}); finished <- err }()
		pid := barrier(t, data, "engine-after-stop-cleanup")
		if state, err := service.Query(service.Engine); err != nil || !state.Running || nativeChildPID(t, data, instance) != pid {
			t.Fatal("acknowledged but still-running service precondition", state, pid, err)
		}
		select {
		case err := <-finished:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(35 * time.Second):
			t.Fatal("accepted stop wedged Control")
		}
		elapsed := time.Since(started)
		if elapsed < 18*time.Second || elapsed > 32*time.Second {
			t.Fatal("forced-stop bound was not exercised", elapsed)
		}
		if state, err := service.Query(service.Engine); err != nil || !state.Stopped {
			t.Fatal("forced stop left the engine alive", state, err)
		}
		directTraffic(t, ctx, fixture)
		if err := service.Stop(ctx, service.Control); err != nil {
			t.Fatal(err)
		}
		t.Logf("FORCED_STOP acknowledged engine held at barrier, service terminated after %s", elapsed)
	})
	t.Run("control-crash-storm-keeps-socket-and-recovers", func(t *testing.T) { controlCrashStorm(t, ctx, owner, fixture) })
	t.Run("enrollment-restarts-do-not-backoff", func(t *testing.T) { enrollmentRestarts(t, ctx, owner, fixture) })
	t.Run("control-restart-delay-decays-after-healthy-run", func(t *testing.T) { controlRestartDelayDecays(t, ctx, owner, fixture) })
	t.Run("CLI-activates-stopped-Control", func(t *testing.T) { cliActivation(t, owner) })
	t.Run("real-tun-fail-open", func(t *testing.T) { tunServices(t, config, owner, fixture) })
}
func binary(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}
func kill(t *testing.T, pid uint32) {
	// Independent fault cases reset Control's automatic-restart delay.
	// The crash-storm case deliberately uses killUnreset throughout.
	if s, err := service.Query(service.Control); err == nil && s.PID == pid {
		resetControlRecoveryWindow(t)
	}
	killUnreset(t, pid)
}
func killUnreset(t *testing.T, pid uint32) {
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
	c, err := localipc.DialNativeEngine(ctx, endpoint)
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
