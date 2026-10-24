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
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/crashnet"
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
	Now                       func() time.Time
	Sleep                     func(context.Context, time.Duration) error
	FreePort                  func() (int, error)
	ports                     func(bool) (int, int, error)
	ID                        func() string
	ListFiles                 func(string) ([]string, error)
	Verify                    func() error
	StartProcess              func(string, string, string) (Child, error)
	NormalizeProcessPath      func(string) string
	PrepareConfig             func([]byte) ([]byte, error)
	Crash                     *crashnet.Net
}
type Child interface {
	PID() int
	Stdout() io.Reader
	Stderr() io.Reader
	Wait() error
	Kill() error
}
type commandChild struct {
	cmd      *exec.Cmd
	out, err io.ReadCloser
}

func (p *commandChild) PID() int          { return p.cmd.Process.Pid }
func (p *commandChild) Stdout() io.Reader { return p.out }
func (p *commandChild) Stderr() io.Reader { return p.err }
func (p *commandChild) Wait() error       { return p.cmd.Wait() }
func (p *commandChild) Kill() error       { return p.cmd.Process.Kill() }
func startProcess(exe, config, dir string) (Child, error) {
	cmd := exec.Command(exe, "run", "-c", config, "--disable-color")
	cmd.Dir = dir
	hide(cmd)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &commandChild{cmd: cmd, out: out, err: stderr}, nil
}

type diskFiles struct{}

func (diskFiles) ReadFile(p string) ([]byte, error)                 { return os.ReadFile(p) }
func (diskFiles) WriteFile(p string, b []byte, m os.FileMode) error { return os.WriteFile(p, b, m) }
func (diskFiles) Rename(a, b string) error                          { return os.Rename(a, b) }
func (diskFiles) Remove(p string) error                             { return os.Remove(p) }

type Adapter struct {
	mu               sync.Mutex
	lifecycle, apply sync.Mutex
	o                Options
	s                engine.Snapshot
	child            Child
	exited           chan struct{}
	apiPort          int
	secret           string
	lastOutput       []string
	closeResults     map[string]engine.CloseResult
	closeOrder       []string
	verified         map[string]verifiedFile
	probeContext     context.Context
	stopProbes       context.CancelFunc
	appliedTimes     map[uint64]time.Time
	observed         map[string]engine.Connection
	laneKnown        map[string]bool
	probeFailures    map[string]time.Time
}
type verifiedFile struct {
	Size     int64
	Modified time.Time
	Hash     string
}

func New(o Options) *Adapter {
	if o.HTTP == nil {
		o.HTTP = &http.Client{}
	}
	if o.Log == nil {
		o.Log = func(string) {}
	}
	if o.Files.Files == nil {
		o.Files.Files = diskFiles{}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = sleep
	}
	if o.ID == nil {
		o.ID = randomID
	}
	if o.FreePort == nil {
		o.ports = func(proxy bool) (int, int, error) {
			return reservePorts(proxy, func() (net.Listener, error) { return net.Listen("tcp4", "127.0.0.1:0") })
		}
	} else {
		// Preserve the deterministic port hook used by the frozen oracle.
		o.ports = func(proxy bool) (int, int, error) {
			api, err := o.FreePort()
			if err != nil || !proxy {
				return api, 0, err
			}
			port, err := o.FreePort()
			return api, port, err
		}
	}
	if o.StartProcess == nil {
		o.StartProcess = startProcess
	}
	if o.ListFiles == nil {
		o.ListFiles = func(dir string) ([]string, error) {
			entries, err := os.ReadDir(dir)
			if err != nil {
				return nil, err
			}
			names := []string{}
			for _, e := range entries {
				names = append(names, e.Name())
			}
			return names, nil
		}
	}
	return &Adapter{o: o, s: engine.Snapshot{Status: "off", Policy: engine.Policy{Lines: []lines.Line{}, AppLines: apps.Pins{}, Shares: lines.Shares{}, Blocked: []string{}, Lanes: map[string]string{}}}, closeResults: map[string]engine.CloseResult{}, verified: map[string]verifiedFile{}, appliedTimes: map[uint64]time.Time{}}
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

// Health checks the forwarding process independently of expensive flow
// snapshots. The service host owns the consecutive-failure window.
func (a *Adapter) Health(ctx context.Context) error {
	_, _, err := a.request(ctx, "GET", "/version", nil)
	return err
}
func (a *Adapter) ForgetLane(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.s.Policy.Lanes, id)
	delete(a.laneKnown, id)
}
func randomID() string {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

// Hold the first reservation while obtaining the second. Releasing each
// before allocating the next lets the OS return the same ephemeral port.
// The legacy child cannot inherit listeners, so release both before launch.
func reservePorts(proxy bool, listen func() (net.Listener, error)) (api, port int, err error) {
	first, err := listen()
	if err != nil {
		return 0, 0, err
	}
	defer func() { err = errors.Join(err, first.Close()) }()
	api = first.Addr().(*net.TCPAddr).Port
	if !proxy {
		return api, 0, nil
	}
	second, err := listen()
	if err != nil {
		return 0, 0, err
	}
	defer func() { err = errors.Join(err, second.Close()) }()
	port = second.Addr().(*net.TCPAddr).Port
	if api == port {
		return 0, 0, errors.New("adapter port reservations overlap")
	}
	return api, port, nil
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
		return b, response.StatusCode, fmt.Errorf("engine %s %s answered %d", method, path, response.StatusCode)
	}
	return b, response.StatusCode, nil
}
func (a *Adapter) Connections(ctx context.Context) ([]engine.Connection, error) {
	instance := a.Snapshot().Instance
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
		if a.o.NormalizeProcessPath != nil {
			c.Metadata.ProcessPath = a.o.NormalizeProcessPath(c.Metadata.ProcessPath)
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
	a.mu.Lock()
	if a.s.Instance == instance {
		a.observed = map[string]engine.Connection{}
		for _, connection := range out {
			a.observed[connection.ID] = connection
		}
	}
	a.mu.Unlock()
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
	if r.OperationID == "" {
		return engine.CloseResult{}, fmt.Errorf("closure intent requires an operation id")
	}
	a.apply.Lock()
	defer a.apply.Unlock()
	a.mu.Lock()
	if r.Instance != a.s.Instance {
		a.mu.Unlock()
		return engine.CloseResult{}, fmt.Errorf("closure intent belongs to another engine instance")
	}
	previous, done := a.closeResults[r.OperationID]
	if r.StartedBefore.IsZero() {
		r.StartedBefore = a.appliedTimes[r.BeforeRevision]
	}
	lifetime := a.probeContext
	a.mu.Unlock()
	if done {
		return previous, nil
	}
	if r.ConnectionIDs != nil && len(r.ConnectionIDs) == 0 {
		return engine.CloseResult{}, nil
	}
	if r.StartedBefore.IsZero() {
		return engine.CloseResult{}, fmt.Errorf("closure intent has no acknowledged apply point")
	}
	if lifetime != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		stop := context.AfterFunc(lifetime, cancel)
		defer stop()
		defer cancel()
	}
	live := map[string]engine.Connection{}
	var connections []engine.Connection
	if r.Line == "" && r.ConnectionIDs != nil {
		// Reconnect uses the poll that selected these IDs, as Node does. Clash
		// IDs are instance-scoped UUIDs; never select again on a delayed retry.
		a.mu.Lock()
		for _, id := range r.ConnectionIDs {
			if c, ok := a.observed[id]; ok {
				live[id] = c
			}
		}
		a.mu.Unlock()
	} else {
		var err error
		connections, err = a.Connections(ctx)
		if err != nil {
			return engine.CloseResult{}, err
		}
		for _, c := range connections {
			live[c.ID] = c
		}
	}
	if r.ConnectionIDs == nil {
		for _, c := range connections {
			if line := apps.ConnectionLine(&c.Connection); line != nil && *line == r.Line {
				r.ConnectionIDs = append(r.ConnectionIDs, c.ID)
			}
		}
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
		if line == nil || (r.Line != "" && *line != r.Line) || err != nil || !started.Before(r.StartedBefore) {
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
	a.mu.Lock()
	instanceContext := a.probeContext
	a.mu.Unlock()
	if instanceContext != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		stop := context.AfterFunc(instanceContext, cancel)
		defer stop()
		defer cancel()
	}
	v, err := a.o.Platform.Call(ctx, "line-check", map[string]any{"line": r.Line, "index": r.Index, "target": r.Target, "quick": r.Quick, "custom": r.Custom, "opId": r.OperationID})
	if err != nil && ctx.Err() == nil {
		a.logProbeFailure(r.Line, err)
	}
	if err != nil || a.Snapshot().Instance != s.Instance || a.Snapshot().Status != "on" {
		return engine.ProbeResult{Outcome: engine.Unavailable}
	}
	b, err := json.Marshal(v)
	if err != nil {
		a.logProbeFailure(r.Line, err)
		return engine.ProbeResult{Outcome: engine.Unavailable}
	}
	var result engine.ProbeResult
	if err = json.Unmarshal(b, &result); err != nil {
		a.logProbeFailure(r.Line, err)
		return engine.ProbeResult{Outcome: engine.Unavailable}
	}
	if result.Outcome != engine.OK && result.Outcome != engine.LineFailed && result.Outcome != engine.Unavailable {
		a.logProbeFailure(r.Line, fmt.Errorf("worker returned invalid outcome %q", result.Outcome))
		return engine.ProbeResult{Outcome: engine.Unavailable}
	}
	// The worker ran exactly the kind requested; Control's acceptance checks
	// (kind and instance) apply to this adapter like to the native engine.
	result.Kind, result.Instance = "full", s.Instance
	if r.Quick {
		result.Kind = "quick"
	}
	return result
}

func (a *Adapter) logProbeFailure(line string, err error) {
	a.mu.Lock()
	if a.probeFailures == nil {
		a.probeFailures = map[string]time.Time{}
	}
	now := a.o.Now()
	last, seen := a.probeFailures[line]
	log := !seen || now.Sub(last) >= 30*time.Second
	if log {
		a.probeFailures[line] = now
	}
	a.mu.Unlock()
	if log {
		a.o.Log(fmt.Sprintf("line-check worker for %s failed: %v; no health vote recorded", line, err))
	}
}

// Apply is serialized and acknowledged after file replacement, the legacy
// reload grace period and selector acknowledgements. sing-box does not expose
// an atomic file-set reload acknowledgement; this is an explicit adapter-only
// limitation, not a claim of packet-level atomicity.
func (a *Adapter) Apply(ctx context.Context, r engine.Revision) (engine.Acknowledgement, error) {
	a.apply.Lock()
	defer a.apply.Unlock()
	encoded, err := js.Marshal(r.Policy)
	if err != nil {
		return engine.Acknowledgement{}, err
	}
	digest := sha256.Sum256(encoded)
	if r.Hash != hex.EncodeToString(digest[:]) {
		return engine.Acknowledgement{}, fmt.Errorf("policy revision payload does not match its hash")
	}
	before := a.Snapshot()
	ack := engine.Acknowledgement{Number: r.Number, Hash: r.Hash, Instance: before.Instance, AppliedAt: before.AppliedAt}
	if r.Number < before.AppliedRevision {
		return engine.Acknowledgement{}, fmt.Errorf("stale policy revision")
	}
	if r.Number == before.AppliedRevision {
		if r.Hash != before.AppliedHash {
			return engine.Acknowledgement{}, fmt.Errorf("policy revision hash conflict")
		}
		return ack, nil
	}
	rulePolicy := clonePolicy(r.Policy)
	if before.Status == "on" && before.StartedWith != nil {
		// Today's selectors/rule tags use the bound line order until restart.
		rulePolicy.Lines = before.StartedWith.Lines
	}
	files, err := RuleFiles(rulePolicy)
	if err != nil {
		return engine.Acknowledgement{}, err
	}
	beforeRules, nextRules := clonePolicy(before.Policy), clonePolicy(r.Policy)
	for _, policy := range []*engine.Policy{&beforeRules, &nextRules} {
		for i := range policy.Lines {
			// Rebinding an adapter changes config on restart, not rule bytes.
			policy.Lines[i].Alias, policy.Lines[i].GUID = "", nil
		}
	}
	beforeRules.Lanes = nil
	nextRules.Lanes = nil
	beforeRules.IPv6 = false
	nextRules.IPv6 = false
	if reflect.DeepEqual(beforeRules, nextRules) {
		files = nil
	}
	if before.Status == "off" && before.StartedWith == nil {
		files = nil
	}
	// Node queues a share rewrite before its blocked-set rewrite. Retain both
	// batches in this temporary adapter, including the intermediate file bytes.
	if r.Policy.Combine && !reflect.DeepEqual(before.Policy.Shares, r.Policy.Shares) && !reflect.DeepEqual(before.Policy.Blocked, r.Policy.Blocked) {
		intermediate := rulePolicy
		intermediate.Blocked = before.Policy.Blocked
		first, err := RuleFiles(intermediate)
		if err != nil {
			return engine.Acknowledgement{}, err
		}
		files = append(first, files...)
	}
	previousRules := clonePolicy(before.Policy)
	if before.Status == "on" && before.StartedWith != nil {
		previousRules.Lines = before.StartedWith.Lines
	}
	old, err := RuleFiles(previousRules)
	if err != nil {
		return engine.Acknowledgement{}, err
	}
	oldBytes := map[string][]byte{}
	for _, f := range old {
		oldBytes[f.Tag] = f.Bytes
	}
	written := []string{}
	rollback := func(cause error) error {
		var failures []string
		for _, tag := range written {
			if b, ok := oldBytes[tag]; ok {
				if err := settings.AtomicWrite(filepath.Join(a.o.DataDir, tag+".json"), b, a.o.Files); err != nil {
					failures = append(failures, err.Error())
				}
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
		if len(files) > 0 {
			if err := a.o.Sleep(ctx, 300*time.Millisecond); err != nil {
				return engine.Acknowledgement{}, rollback(err)
			}
		}
		if a.Snapshot().Status != "on" {
			return engine.Acknowledgement{}, rollback(fmt.Errorf("routing engine stopped while reloading rules"))
		}
		// Rule writes have finished. A failed selector must not revert those
		// rules (or other successful selectors), nor reload them on every poll.
		a.mu.Lock()
		a.s.Policy = clonePolicy(r.Policy)
		a.s.Policy.Lanes = clonePolicy(before.Policy).Lanes
		if a.laneKnown == nil {
			a.laneKnown = map[string]bool{}
		}
		a.mu.Unlock()
		if before.StartedWith != nil && len(before.StartedWith.Lines) > 1 {
			existing := map[string]bool{}
			for _, l := range before.StartedWith.Lines {
				existing[l.ID] = true
			}
			for _, l := range r.Policy.Lines {
				target := r.Policy.Lanes[l.ID]
				a.mu.Lock()
				known := a.laneKnown[l.ID]
				a.mu.Unlock()
				if !existing[l.ID] || !existing[target] || target == "" || (known && before.Policy.Lanes[l.ID] == target) {
					continue
				}
				if _, _, err := a.request(ctx, "PUT", "/proxies/"+url.PathEscape(apps.LaneSelector(l.ID)), map[string]any{"name": apps.LineOutbound(target)}); err != nil {
					return engine.Acknowledgement{}, err
				}
				a.mu.Lock()
				a.s.Policy.Lanes[l.ID] = target
				a.laneKnown[l.ID] = true
				a.mu.Unlock()
			}
		}
	}
	a.mu.Lock()
	a.s.Policy = clonePolicy(r.Policy)
	a.s.AppliedRevision = r.Number
	a.s.AppliedHash = r.Hash
	ack.AppliedAt = a.o.Now()
	a.s.AppliedAt = ack.AppliedAt
	a.appliedTimes[r.Number] = ack.AppliedAt
	a.mu.Unlock()
	return ack, nil
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
	if runtime.GOOS == "windows" && arch != "arm64" {
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
		file := filepath.Join(dir, name)
		info, err := os.Stat(file)
		if err != nil {
			return fmt.Errorf("engine %s is missing: %w", name, err)
		}
		stamp := verifiedFile{Size: info.Size(), Modified: info.ModTime(), Hash: want}
		if a.verified[file] == stamp {
			continue
		}
		f, err := os.Open(file)
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
		a.verified[file] = stamp
	}
	return nil
}
func (a *Adapter) stopOrphan(ctx context.Context) error {
	pidFile := filepath.Join(a.o.DataDir, "engine.pid")
	b, err := a.o.Files.Files.ReadFile(pidFile)
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
	a.removePID()
	return nil
}

func (a *Adapter) removePID() {
	if err := a.o.Files.Files.Remove(filepath.Join(a.o.DataDir, "engine.pid")); err != nil && !os.IsNotExist(err) {
		a.o.Log(fmt.Sprintf("cleanup warning: could not remove engine.pid after routing stopped: %v", err))
	}
}

// A child remains owned until its exit goroutine has finished PID cleanup, even
// after child becomes nil. Never let orphan cleanup compete with that owner.
func (a *Adapter) stopPrevious(ctx context.Context) error {
	a.mu.Lock()
	owned := a.exited != nil
	a.mu.Unlock()
	if owned {
		return a.stopChild(ctx)
	}
	return a.stopOrphan(ctx)
}
func (a *Adapter) Start(ctx context.Context, p engine.Policy) error {
	a.lifecycle.Lock()
	defer a.lifecycle.Unlock()
	if a.Snapshot().Status == "on" {
		return nil
	}
	if len(p.Lines) == 0 {
		a.status("error", fmt.Errorf("No internet connection was found. Connect one, then turn routing on."))
		return nil
	}
	a.status("starting", nil)
	a.mu.Lock()
	a.lastOutput = nil
	a.mu.Unlock()
	err := a.start(ctx, p)
	if err != nil {
		_ = a.stopChild(ctx)
		a.mu.Lock()
		details := append([]string{}, a.lastOutput[max(0, len(a.lastOutput)-6):]...)
		a.mu.Unlock()
		suffix := ""
		if len(details) > 0 {
			suffix = "\n" + strings.Join(details, "\n")
		}
		a.status("error", fmt.Errorf("Routing couldn't start. %w%s", err, suffix))
		return nil
	}
	return err
}
func (a *Adapter) start(ctx context.Context, p engine.Policy) error {
	if len(p.Lines) == 0 {
		return fmt.Errorf("No internet connection was found. Connect one, then turn routing on.")
	}
	if err := a.stopPrevious(ctx); err != nil {
		return err
	}
	verify := a.o.Verify
	if verify == nil {
		verify = a.verify
	}
	if err := verify(); err != nil {
		return err
	}
	apiPort, proxyPort, err := a.o.ports(a.o.Mode == "proxy")
	if err != nil {
		return err
	}
	secret := a.o.ID()
	if a.o.FreePort == nil { // actual OS reservations, not oracle-supplied ports
		a.o.Log(fmt.Sprintf("adapter listener ports: api=%d proxy=%d", apiPort, proxyPort))
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
	entries, _ := a.o.ListFiles(a.o.DataDir)
	for _, e := range entries {
		if (stale.MatchString(e) && !keep[e]) || e == "second-apps.json" {
			_ = a.o.Files.Files.Remove(filepath.Join(a.o.DataDir, e))
		}
	}
	b, err := ConfigBytes(ConfigOptions{a.o.Mode, p.Lines, apiPort, secret, proxyPort, a.o.DataDir, p.IPv6})
	if err == nil && a.o.PrepareConfig != nil {
		b, err = a.o.PrepareConfig(b)
	}
	if err != nil {
		return err
	}
	file := filepath.Join(a.o.DataDir, "engine-config.json")
	if err := a.o.Files.Files.WriteFile(file, b, 0600); err != nil {
		return err
	}
	cmd, err := a.o.StartProcess(a.o.Executable, file, a.o.DataDir)
	if err != nil {
		return err
	}
	out, stderr := cmd.Stdout(), cmd.Stderr()
	exited := make(chan struct{})
	a.mu.Lock()
	a.child = cmd
	a.exited = exited
	a.apiPort = apiPort
	a.secret = secret
	a.s.PID = cmd.PID()
	a.s.Instance = a.o.ID()
	if a.stopProbes != nil {
		a.stopProbes()
	}
	a.probeContext, a.stopProbes = context.WithCancel(context.Background())
	a.s.AppliedRevision = 0
	a.s.AppliedHash = ""
	a.appliedTimes = map[uint64]time.Time{}
	a.observed = nil
	a.laneKnown = map[string]bool{}
	a.probeFailures = map[string]time.Time{}
	a.closeResults = map[string]engine.CloseResult{}
	a.closeOrder = nil
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
	// Publish the PID before an immediate child exit can remove it. Even if
	// writing fails, install the exit owner so the start failure can await it.
	pidErr := a.o.Files.Files.WriteFile(filepath.Join(a.o.DataDir, "engine.pid"), []byte(strconv.Itoa(cmd.PID())), 0600)
	go func() { defer readers.Done(); defer a.o.Crash.Recover("engine stdout"); collect(out) }()
	go func() { defer readers.Done(); defer a.o.Crash.Recover("engine stderr"); collect(stderr) }()
	go func() {
		defer close(exited)
		defer a.o.Crash.Recover("engine supervisor")
		readers.Wait()
		err := cmd.Wait()
		a.mu.Lock()
		own := a.child == cmd
		if own {
			a.child = nil
			if a.stopProbes != nil {
				a.stopProbes()
			}
			if a.s.Status != "stopping" && a.s.Status != "starting" {
				code := "0"
				if err != nil {
					code = "null"
					var exit interface{ ExitCode() int }
					if errors.As(err, &exit) && exit.ExitCode() >= 0 {
						code = strconv.Itoa(exit.ExitCode())
					}
				}
				message := fmt.Sprintf("Routing stopped unexpectedly (exit code %s).", code)
				if len(a.lastOutput) > 0 {
					message += "\n" + strings.Join(a.lastOutput[max(0, len(a.lastOutput)-6):], "\n")
				}
				a.s.Status = "error"
				a.s.Error = &message
			}
		}
		a.mu.Unlock()
		if own {
			a.removePID()
		}
	}()
	if pidErr != nil {
		return pidErr
	}
	deadline := a.o.Now().Add(15 * time.Second)
	for a.o.Now().Before(deadline) {
		select {
		case <-exited:
			return fmt.Errorf("The routing engine closed while starting.")
		default:
		}
		if _, _, err := a.request(ctx, "GET", "/version", nil); err == nil {
			a.mu.Lock()
			if a.child != cmd {
				a.mu.Unlock()
				return fmt.Errorf("The routing engine closed while starting.")
			}
			copy := clonePolicy(p)
			a.s.StartedWith = &copy
			a.s.Policy = clonePolicy(p)
			for _, line := range p.Lines {
				a.s.Policy.Lanes[line.ID] = line.ID
			}
			a.s.StartedAt = a.o.Now()
			a.s.Status = "on"
			a.s.Error = nil
			a.mu.Unlock()
			return nil
		}
		if err := a.o.Sleep(ctx, 250*time.Millisecond); err != nil {
			return err
		}
	}
	return fmt.Errorf("The routing engine did not respond within 15 seconds.")
}
func (a *Adapter) stopChild(ctx context.Context) error {
	a.mu.Lock()
	child, exited := a.child, a.exited
	a.mu.Unlock()
	if exited == nil {
		return nil
	}
	if child != nil {
		if err := child.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(8 * time.Second):
		return fmt.Errorf("routing engine did not finish stopping")
	case <-exited:
	}
	// Ownership ends only after the sole deletion attempt has completed. A
	// later lifecycle operation may then clean a newly discovered orphan PID,
	// without adding a second delete to this child's Stop operation.
	a.mu.Lock()
	if a.exited == exited {
		a.exited = nil
	}
	a.mu.Unlock()
	return nil
}
func (a *Adapter) Stop(ctx context.Context) error {
	a.lifecycle.Lock()
	defer a.lifecycle.Unlock()
	a.mu.Lock()
	if a.stopProbes != nil {
		a.stopProbes()
	}
	a.mu.Unlock()
	a.status("stopping", nil)
	a.apply.Lock()
	defer a.apply.Unlock()
	if err := a.stopPrevious(ctx); err != nil {
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
