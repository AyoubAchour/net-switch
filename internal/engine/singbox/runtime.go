package singbox

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/engine"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
	"github.com/AyoubAchour/net-switch/internal/lines"
	"github.com/AyoubAchour/net-switch/internal/platform"
	"github.com/AyoubAchour/net-switch/internal/settings"
)

type Options struct {
	Executable, DataDir, Mode string
	Platform                  platform.System
	HTTP                      *http.Client
	Log                       func(string)
	Files                     settings.Options
}
type Adapter struct {
	mu               sync.Mutex
	lifecycle, apply sync.Mutex
	o                Options
	s                engine.Snapshot
	child            *exec.Cmd
	exited           chan struct{}
	apiPort          int
	secret           string
	lastOutput       []string
	closeResults     map[string]engine.CloseResult
	closeOrder       []string
}

func New(o Options) *Adapter {
	if o.HTTP == nil {
		o.HTTP = &http.Client{}
	}
	if o.Log == nil {
		o.Log = func(string) {}
	}
	return &Adapter{o: o, s: engine.Snapshot{Status: "off", Policy: engine.Policy{Lines: []lines.Line{}, AppLines: apps.Pins{}, Shares: lines.Shares{}, Blocked: []string{}, Lanes: map[string]string{}}}, closeResults: map[string]engine.CloseResult{}}
}
func clonePolicy(p engine.Policy) engine.Policy {
	p.Lines = append([]lines.Line{}, p.Lines...)
	p.AppLines = append(apps.Pins{}, p.AppLines...)
	p.Shares = append(lines.Shares{}, p.Shares...)
	p.Blocked = append([]string{}, p.Blocked...)
	m := map[string]string{}
	for k, v := range p.Lanes {
		m[k] = v
	}
	p.Lanes = m
	return p
}
func (a *Adapter) Snapshot() engine.Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.s
	s.Policy = clonePolicy(s.Policy)
	if s.StartedWith != nil {
		p := clonePolicy(*s.StartedWith)
		s.StartedWith = &p
	}
	return s
}
func (a *Adapter) status(status string, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.s.Status = status
	a.s.Error = nil
	if err != nil {
		s := err.Error()
		a.s.Error = &s
	}
}
func (a *Adapter) Fail(err error) { a.status("error", err) }
func randomID() string {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func freePort() (int, error) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	p := l.Addr().(*net.TCPAddr).Port
	return p, l.Close()
}
func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func (a *Adapter) request(ctx context.Context, method, path string, body any) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var reader io.Reader
	if body != nil {
		b, err := js.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		reader = bytes.NewReader(b)
	}
	a.mu.Lock()
	port, secret := a.apiPort, a.secret
	a.mu.Unlock()
	r, err := http.NewRequestWithContext(ctx, method, fmt.Sprintf("http://127.0.0.1:%d%s", port, path), reader)
	if err != nil {
		return nil, 0, err
	}
	r.Header.Set("Authorization", "Bearer "+secret)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	response, err := a.o.HTTP.Do(r)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	b, err := io.ReadAll(io.LimitReader(response.Body, 16*1024*1024))
	if err != nil {
		return nil, response.StatusCode, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return b, response.StatusCode, fmt.Errorf("engine answered %d", response.StatusCode)
	}
	return b, response.StatusCode, nil
}
func (a *Adapter) Connections(ctx context.Context) ([]engine.Connection, error) {
	b, _, err := a.request(ctx, "GET", "/connections", nil)
	if err != nil {
		return nil, err
	}
	var response struct {
		Connections []json.RawMessage `json:"connections"`
	}
	if err := json.Unmarshal(b, &response); err != nil {
		return nil, err
	}
	out := []engine.Connection{}
	for _, raw := range response.Connections {
		var c apps.Connection
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, err
		}
		var meta struct {
			Metadata struct {
				Host string `json:"host"`
				IP   string `json:"destinationIP"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(raw, &meta); err != nil {
			return nil, err
		}
		host := meta.Metadata.Host
		if host == "" {
			host = meta.Metadata.IP
		}
		out = append(out, engine.Connection{Connection: c, Host: host})
	}
	return out, nil
}
func (a *Adapter) CloseConnection(ctx context.Context, id string) error {
	_, status, err := a.request(ctx, "DELETE", "/connections/"+url.PathEscape(id), nil)
	if status == 404 {
		return nil
	}
	return err
}
func (a *Adapter) CloseFlows(ctx context.Context, r engine.CloseRequest) (engine.CloseResult, error) {
	a.apply.Lock()
	defer a.apply.Unlock()
	a.mu.Lock()
	if r.Instance != a.s.Instance {
		a.mu.Unlock()
		return engine.CloseResult{}, fmt.Errorf("closure intent belongs to another engine instance")
	}
	previous, done := a.closeResults[r.OperationID]
	a.mu.Unlock()
	if done {
		return previous, nil
	}
	connections, err := a.Connections(ctx)
	if err != nil {
		return engine.CloseResult{}, err
	}
	live := map[string]engine.Connection{}
	for _, c := range connections {
		live[c.ID] = c
	}
	result := engine.CloseResult{}
	for _, id := range r.ConnectionIDs {
		c, ok := live[id]
		if !ok {
			result.Gone++
			continue
		}
		line := apps.ConnectionLine(&c.Connection)
		started, err := time.Parse(time.RFC3339Nano, c.Start)
		if line == nil || *line != r.Line || err != nil || !started.Before(r.StartedBefore) {
			result.Gone++
			continue
		}
		if err := a.CloseConnection(ctx, id); err != nil {
			result.Failed++
		} else {
			result.Closed++
		}
	}
	if result.Failed == 0 {
		a.mu.Lock()
		a.closeResults[r.OperationID] = result
		a.closeOrder = append(a.closeOrder, r.OperationID)
		if len(a.closeOrder) > 1024 {
			delete(a.closeResults, a.closeOrder[0])
			a.closeOrder = a.closeOrder[1:]
		}
		a.mu.Unlock()
	}
	return result, nil
}
func (a *Adapter) Probe(ctx context.Context, r engine.ProbeRequest) engine.ProbeResult {
	s := a.Snapshot()
	if s.Status != "on" || a.o.Platform == nil {
		return engine.ProbeResult{Outcome: engine.Unavailable}
	}
	v, err := a.o.Platform.Call(ctx, "line-check", map[string]any{"index": r.Index, "target": r.Target, "quick": r.Quick, "opId": r.OperationID})
	if err != nil || a.Snapshot().Instance != s.Instance || a.Snapshot().Status != "on" {
		return engine.ProbeResult{Outcome: engine.Unavailable}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return engine.ProbeResult{Outcome: engine.Unavailable}
	}
	var result engine.ProbeResult
	if err = json.Unmarshal(b, &result); err != nil {
		return engine.ProbeResult{Outcome: engine.Unavailable}
	}
	return result
}

// Apply is serialized and acknowledged after file replacement, the legacy
// reload grace period and selector acknowledgements. sing-box does not expose
// an atomic file-set reload acknowledgement; this is an explicit adapter-only
// limitation, not a claim of packet-level atomicity.
func (a *Adapter) Apply(ctx context.Context, r engine.Revision) (engine.Acknowledgement, error) {
	a.apply.Lock()
	defer a.apply.Unlock()
	before := a.Snapshot()
	ack := func() engine.Acknowledgement {
		return engine.Acknowledgement{Number: r.Number, Hash: r.Hash, Instance: before.Instance, AppliedAt: time.Now()}
	}
	if r.Number < before.AppliedRevision {
		return engine.Acknowledgement{}, fmt.Errorf("stale policy revision")
	}
	if r.Number == before.AppliedRevision {
		if r.Hash != before.AppliedHash {
			return engine.Acknowledgement{}, fmt.Errorf("policy revision hash conflict")
		}
		return ack(), nil
	}
	files, err := RuleFiles(r.Policy)
	if err != nil {
		return engine.Acknowledgement{}, err
	}
	old, err := RuleFiles(before.Policy)
	if err != nil {
		return engine.Acknowledgement{}, err
	}
	oldBytes := map[string][]byte{}
	for _, f := range old {
		oldBytes[f.Tag] = f.Bytes
	}
	written := []string{}
	moved := []string{}
	rollback := func(cause error) error {
		var failures []string
		for _, tag := range written {
			if b, ok := oldBytes[tag]; ok {
				if err := settings.AtomicWrite(filepath.Join(a.o.DataDir, tag+".json"), b, a.o.Files); err != nil {
					failures = append(failures, err.Error())
				}
			}
		}
		for _, id := range moved {
			target := before.Policy.Lanes[id]
			if target == "" {
				target = id
			}
			if _, _, err := a.request(ctx, "PUT", "/proxies/"+url.PathEscape(apps.LaneSelector(id)), map[string]any{"name": apps.LineOutbound(target)}); err != nil {
				failures = append(failures, err.Error())
			}
		}
		if len(failures) > 0 {
			return fmt.Errorf("apply failed: %w; rollback failed: %s", cause, strings.Join(failures, "; "))
		}
		return cause
	}
	for _, f := range files {
		if err := settings.AtomicWrite(filepath.Join(a.o.DataDir, f.Tag+".json"), f.Bytes, a.o.Files); err != nil {
			return engine.Acknowledgement{}, rollback(err)
		}
		written = append(written, f.Tag)
	}
	if before.Status == "on" {
		if err := sleep(ctx, 300*time.Millisecond); err != nil {
			return engine.Acknowledgement{}, rollback(err)
		}
		if _, _, err := a.request(ctx, "GET", "/version", nil); err != nil {
			return engine.Acknowledgement{}, rollback(err)
		}
		if before.StartedWith != nil && len(before.StartedWith.Lines) > 1 {
			existing := map[string]bool{}
			for _, l := range before.StartedWith.Lines {
				existing[l.ID] = true
			}
			for _, l := range r.Policy.Lines {
				target := r.Policy.Lanes[l.ID]
				if !existing[l.ID] || !existing[target] || target == "" || before.Policy.Lanes[l.ID] == target {
					continue
				}
				if _, _, err := a.request(ctx, "PUT", "/proxies/"+url.PathEscape(apps.LaneSelector(l.ID)), map[string]any{"name": apps.LineOutbound(target)}); err != nil {
					return engine.Acknowledgement{}, rollback(err)
				}
				moved = append(moved, l.ID)
			}
		}
	}
	a.mu.Lock()
	a.s.Policy = clonePolicy(r.Policy)
	a.s.AppliedRevision = r.Number
	a.s.AppliedHash = r.Hash
	a.mu.Unlock()
	return ack(), nil
}
func (a *Adapter) verify() error {
	dir := filepath.Dir(a.o.Executable)
	name := "SHA256SUMS.txt"
	arch := runtime.GOARCH
	if _, err := os.Stat(filepath.Join(dir, "SHA256SUMS-arm64.txt")); err == nil {
		if a.o.Platform != nil {
			v, err := a.o.Platform.Call(context.Background(), "architecture", nil)
			if err != nil {
				return err
			}
			arch = js.Text(v)
		}
		if arch == "arm64" {
			name = "SHA256SUMS-arm64.txt"
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return fmt.Errorf("engine checksum list: %w", err)
	}
	pattern := regexp.MustCompile(`(?i)^([0-9a-f]{64})\s+\*?(\S+)\s*$`)
	sums := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		if m := pattern.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
			sums[m[2]] = strings.ToLower(m[1])
		}
	}
	required := []string{filepath.Base(a.o.Executable)}
	if arch != "arm64" {
		required = append(required, "libcronet.dll")
	}
	for _, name := range required {
		if sums[name] == "" {
			return fmt.Errorf("engine checksum list has no line for %s", name)
		}
	}
	for name, want := range sums {
		if filepath.Base(name) != name || strings.ContainsAny(name, `/\`) {
			return fmt.Errorf("invalid checksum filename %q", name)
		}
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			return fmt.Errorf("engine %s is missing: %w", name, err)
		}
		hash := sha256.New()
		_, err = io.Copy(hash, f)
		f.Close()
		if err != nil {
			return err
		}
		if hex.EncodeToString(hash.Sum(nil)) != want {
			return fmt.Errorf("engine %s doesn’t match %s", name, want)
		}
	}
	return nil
}
func (a *Adapter) stopOrphan(ctx context.Context) error {
	pidFile := filepath.Join(a.o.DataDir, "engine.pid")
	b, err := os.ReadFile(pidFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	pid, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
	if err == nil && pid > 0 {
		if a.o.Platform == nil {
			return fmt.Errorf("cannot identify orphan engine")
		}
		if _, err := a.o.Platform.Call(ctx, "stop-process", map[string]any{"pid": pid, "path": a.o.Executable}); err != nil {
			return err
		}
	}
	return os.Remove(pidFile)
}
func (a *Adapter) Start(ctx context.Context, p engine.Policy) error {
	a.lifecycle.Lock()
	defer a.lifecycle.Unlock()
	if a.Snapshot().Status == "on" {
		return nil
	}
	a.status("starting", nil)
	err := a.start(ctx, p)
	if err != nil {
		_ = a.stopChild(ctx)
		a.status("error", fmt.Errorf("Routing couldn't start. %w", err))
	}
	return err
}
func (a *Adapter) start(ctx context.Context, p engine.Policy) error {
	if len(p.Lines) == 0 {
		return fmt.Errorf("No internet connection was found. Connect one, then turn routing on.")
	}
	if err := a.stopOrphan(ctx); err != nil {
		return err
	}
	if err := a.verify(); err != nil {
		return err
	}
	apiPort, err := freePort()
	if err != nil {
		return err
	}
	secret := randomID()
	proxyPort := 0
	if a.o.Mode == "proxy" {
		proxyPort, err = freePort()
		if err != nil {
			return err
		}
	}
	a.apply.Lock()
	defer a.apply.Unlock()
	files, err := RuleFiles(p)
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, f := range files {
		keep[f.Tag+".json"] = true
		if err := settings.AtomicWrite(filepath.Join(a.o.DataDir, f.Tag+".json"), f.Bytes, a.o.Files); err != nil {
			return err
		}
	}
	stale := regexp.MustCompile(`^(apps|share|cut)-[0-9a-f]+\.json$`)
	entries, err := os.ReadDir(a.o.DataDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if (stale.MatchString(e.Name()) && !keep[e.Name()]) || e.Name() == "second-apps.json" {
			if err := os.Remove(filepath.Join(a.o.DataDir, e.Name())); err != nil {
				return err
			}
		}
	}
	b, err := ConfigBytes(ConfigOptions{a.o.Mode, p.Lines, apiPort, secret, proxyPort, a.o.DataDir, p.IPv6})
	if err != nil {
		return err
	}
	file := filepath.Join(a.o.DataDir, "engine-config.json")
	if err := os.WriteFile(file, b, 0600); err != nil {
		return err
	}
	cmd := exec.Command(a.o.Executable, "run", "-c", file, "--disable-color")
	cmd.Dir = a.o.DataDir
	hide(cmd)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	exited := make(chan struct{})
	a.mu.Lock()
	a.child = cmd
	a.exited = exited
	a.apiPort = apiPort
	a.secret = secret
	a.s.PID = cmd.Process.Pid
	a.s.Instance = randomID()
	a.s.AppliedRevision = 0
	a.s.AppliedHash = ""
	a.s.ProxyPort = nil
	if proxyPort > 0 {
		a.s.ProxyPort = &proxyPort
	}
	a.lastOutput = nil
	a.mu.Unlock()
	collect := func(r io.Reader) {
		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, 4096), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			a.o.Log(line)
			a.mu.Lock()
			a.lastOutput = append(a.lastOutput, line)
			if len(a.lastOutput) > 40 {
				a.lastOutput = a.lastOutput[1:]
			}
			a.mu.Unlock()
		}
	}
	var readers sync.WaitGroup
	readers.Add(2)
	go func() { defer readers.Done(); collect(out) }()
	go func() { defer readers.Done(); collect(stderr) }()
	go func() {
		readers.Wait()
		err := cmd.Wait()
		a.mu.Lock()
		if a.child == cmd {
			a.child = nil
			if a.s.Status != "stopping" && a.s.Status != "starting" {
				message := fmt.Sprintf("Routing stopped unexpectedly: %v", err)
				a.s.Status = "error"
				a.s.Error = &message
			}
		}
		a.mu.Unlock()
		close(exited)
	}()
	if err := os.WriteFile(filepath.Join(a.o.DataDir, "engine.pid"), []byte(strconv.Itoa(cmd.Process.Pid)), 0600); err != nil {
		return err
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-exited:
			return fmt.Errorf("the routing engine closed while starting")
		default:
		}
		if _, _, err := a.request(ctx, "GET", "/version", nil); err == nil {
			a.mu.Lock()
			copy := clonePolicy(p)
			a.s.StartedWith = &copy
			a.s.Policy = clonePolicy(p)
			for _, line := range p.Lines {
				a.s.Policy.Lanes[line.ID] = line.ID
			}
			a.s.StartedAt = time.Now()
			a.s.Status = "on"
			a.s.Error = nil
			a.mu.Unlock()
			return nil
		}
		if err := sleep(ctx, 250*time.Millisecond); err != nil {
			return err
		}
	}
	return fmt.Errorf("the routing engine did not respond within 15 seconds")
}
func (a *Adapter) stopChild(ctx context.Context) error {
	a.mu.Lock()
	child, exited := a.child, a.exited
	a.mu.Unlock()
	if child == nil {
		return nil
	}
	if err := child.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(8 * time.Second):
		return fmt.Errorf("routing engine %d did not stop", child.Process.Pid)
	case <-exited:
	}
	if err := os.Remove(filepath.Join(a.o.DataDir, "engine.pid")); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
func (a *Adapter) Stop(ctx context.Context) error {
	a.lifecycle.Lock()
	defer a.lifecycle.Unlock()
	a.status("stopping", nil)
	a.apply.Lock()
	defer a.apply.Unlock()
	if err := a.stopChild(ctx); err != nil {
		a.status("error", err)
		return err
	}
	if err := a.stopOrphan(ctx); err != nil {
		a.status("error", err)
		return err
	}
	a.mu.Lock()
	a.s.PID = 0
	a.s.AppliedRevision = 0
	a.s.AppliedHash = ""
	a.mu.Unlock()
	a.status("off", nil)
	return nil
}
