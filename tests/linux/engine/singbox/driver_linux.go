//go:build linux

package singbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/engine"
	"github.com/AyoubAchour/net-switch/tests/linux/harness"
	"github.com/AyoubAchour/net-switch/tests/linux/netns"
)

// The Linux layout (LINUX-PLAN.md section 0): our own table and rule indexes,
// our "to <local range> lookup main" rules just before sing-box's, and one
// table per line with "from <line address>" rules for strict rp_filter.
const (
	apiAddr        = "127.0.0.1:9090"
	tableIndex     = 3110
	ruleIndex      = 31100
	localRulePref  = 31090
	sourceRulePref = 31095
	lineTableBase  = 3200
	tunName        = "NetSwitch"
	// sing-box reloads a changed rule file on its own; give it this long.
	ruleSettle = time.Second
)

// localRanges are lib/engine.mjs LOCAL_RANGES.
var localRanges = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
	"fc00::/7", "fe80::/10", "ff00::/8",
}

// Options locate the programs the driver uses.
type Options struct {
	Binary   string // sing-box
	Expect   string // the version packaging/versions.json pins
	Node     string // node, to run config.mjs
	RepoRoot string // the checkout, for lib/engine.mjs
}

// Driver is the baseline engine driver.
type Driver struct {
	opts Options
	exe  harness.Executable

	mu      sync.Mutex
	env     engine.Env
	cfg     engine.Config
	lanes   map[engine.LineID]engine.LineID
	secret  string
	cmd     *exec.Cmd
	done    chan struct{}
	logFile *os.File
	client  *http.Client
	// What this driver created around sing-box, as the exact `ip` arguments
	// that added it, in creation order.
	own [][]string
	// Rules sing-box added at start, as `ip rule show` lines, per family.
	engineRules map[string][]string
}

// New makes the driver.
func New(opts Options) *Driver {
	return &Driver{opts: opts, exe: harness.Executable{Role: "engine", Name: "sing-box", Path: opts.Binary}}
}

// Executable implements engine.Driver.
func (d *Driver) Executable() harness.Executable { return d.exe }

// Kind implements engine.Driver.
func (d *Driver) Kind() harness.EngineKind { return harness.Baseline }

// LogPath implements engine.Driver.
func (d *Driver) LogPath() string { return filepath.Join(d.env.WorkDir, "engine.log") }

var versionLine = regexp.MustCompile(`(?m)^sing-box version (\S+)`)

// Prepare checks sing-box, its pinned version and Node.
func (d *Driver) Prepare(ctx context.Context) error {
	sum, err := harness.FileSHA256(d.opts.Binary)
	if err != nil {
		return fmt.Errorf("sing-box: %w", err)
	}
	d.exe.SHA256 = sum
	out, err := exec.CommandContext(ctx, d.opts.Binary, "version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("sing-box version: %v: %s", err, out)
	}
	m := versionLine.FindSubmatch(out)
	if m == nil {
		return fmt.Errorf("sing-box version printed no version: %s", out)
	}
	d.exe.Version = string(m[1])
	if d.opts.Expect != "" && d.exe.Version != d.opts.Expect {
		return fmt.Errorf("sing-box is %s, but packaging/versions.json pins %s", d.exe.Version, d.opts.Expect)
	}
	if _, err := exec.CommandContext(ctx, d.opts.Node, "--version").Output(); err != nil {
		return fmt.Errorf("node (%s), needed to run Net Switch's config generator: %w", d.opts.Node, err)
	}
	if _, err := os.Stat(d.script()); err != nil {
		return err
	}
	return nil
}

func (d *Driver) script() string {
	return filepath.Join(d.opts.RepoRoot, "tests", "linux", "engine", "singbox", "config.mjs")
}

func (d *Driver) logf(format string, args ...any) {
	if d.env.Logf != nil {
		d.env.Logf("sing-box driver: "+format, args...)
	}
}

func (d *Driver) ip(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"-n", d.env.Netns}, args...)
	out, err := exec.CommandContext(ctx, "ip", full...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("ip %s: %v: %s", strings.Join(full, " "), err, text)
	}
	return text, nil
}

// Start implements engine.Driver.
func (d *Driver) Start(ctx context.Context, env engine.Env, cfg engine.Config) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.running() {
		return errors.New("sing-box is already running")
	}
	d.env, d.cfg = env, cfg
	d.lanes = map[engine.LineID]engine.LineID{}
	if err := os.MkdirAll(env.WorkDir, 0o755); err != nil {
		return err
	}
	if d.secret == "" {
		var b [16]byte
		_, _ = rand.Read(b[:])
		d.secret = hex.EncodeToString(b[:])
	}
	d.client = &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{DialContext: netns.Dialer(env.Netns), DisableKeepAlives: true},
	}
	before, err := d.rules(ctx)
	if err != nil {
		return err
	}
	var exclude []string
	if cfg.Profile == engine.ProfileLinux {
		if err := d.addLinuxRouting(ctx); err != nil {
			return errors.Join(err, d.removeOwn(ctx))
		}
		if exclude, err = d.bridges(ctx); err != nil {
			return errors.Join(err, d.removeOwn(ctx))
		}
	}
	if err := d.generate(ctx, cfg.Policy, false, exclude); err != nil {
		return errors.Join(err, d.removeOwn(ctx))
	}
	if err := d.launch(ctx); err != nil {
		return errors.Join(err, d.removeOwn(ctx))
	}
	after, err := d.rules(ctx)
	if err != nil {
		return err
	}
	d.engineRules = map[string][]string{}
	for family, lines := range after {
		for _, line := range lines {
			if !slices.Contains(before[family], line) && !d.ownRule(family, line) {
				d.engineRules[family] = append(d.engineRules[family], line)
			}
		}
	}
	lanes := map[engine.LineID]engine.LineID{}
	for lane, target := range cfg.Lanes {
		if lane != target {
			lanes[lane] = target
		}
	}
	if len(lanes) > 0 {
		return d.setLanes(ctx, lanes)
	}
	return nil
}

// generate writes config.json (unless rulesOnly) and the rule files.
func (d *Driver) generate(ctx context.Context, p engine.Policy, rulesOnly bool, exclude []string) error {
	type line struct {
		ID    string `json:"id"`
		Alias string `json:"alias"`
	}
	spec := map[string]any{
		"out":               d.env.WorkDir,
		"rulesOnly":         rulesOnly,
		"profile":           "linux",
		"apiPort":           9090,
		"secret":            d.secret,
		"tableIndex":        tableIndex,
		"ruleIndex":         ruleIndex,
		"excludeInterfaces": exclude,
		"logLevel":          "warn",
		"ipv6":              p.IPv6,
		"combine":           p.Combine,
		"blocked":           p.Blocked,
	}
	if d.cfg.Profile == engine.ProfileProduct {
		spec["profile"] = "product"
	}
	var lines []line
	for _, l := range d.cfg.Lines {
		lines = append(lines, line{string(l.ID), l.Interface})
	}
	spec["lines"] = lines
	// Today's app pins programs by path; it has no other identity.
	appLines := map[string]string{}
	for _, pin := range p.Pins {
		appLines[pin.App.Path] = string(pin.Line)
	}
	spec["appLines"] = appLines
	shares := map[string]float64{}
	for id, share := range p.Shares {
		shares[string(id)] = share
	}
	spec["shares"] = shares
	input, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, d.opts.Node, d.script())
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("config.mjs: %v: %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(d.env.WorkDir, "spec.json"), input, 0o644); err != nil {
		return err
	}
	return nil
}

func (d *Driver) launch(ctx context.Context) error {
	logFile, err := os.OpenFile(d.LogPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	// `ip netns exec` execs sing-box in place, so the process is sing-box.
	cmd := exec.Command("ip", "netns", "exec", d.env.Netns, d.opts.Binary, "run", "-c", filepath.Join(d.env.WorkDir, "config.json"), "--disable-color")
	cmd.Dir = d.env.WorkDir
	cmd.Stdout, cmd.Stderr = logFile, logFile
	cmd.Env = append(os.Environ(), "GOTRACEBACK=all")
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return err
	}
	d.cmd, d.logFile, d.done = cmd, logFile, make(chan struct{})
	done := d.done
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if !d.running() {
			return fmt.Errorf("sing-box exited while starting: %s", d.tail(15))
		}
		if d.apiReady(ctx) {
			if _, err := d.ip(ctx, "link", "show", tunName); err == nil {
				d.logf("started, pid %d", cmd.Process.Pid)
				return nil
			}
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			d.kill()
			return fmt.Errorf("sing-box didn't come up within 20 s: %s", d.tail(15))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (d *Driver) tail(n int) string {
	data, _ := os.ReadFile(d.LogPath())
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

func (d *Driver) running() bool {
	if d.done == nil {
		return false
	}
	select {
	case <-d.done:
		return false
	default:
		return true
	}
}

// Running implements engine.Driver.
func (d *Driver) Running() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.running()
}

func (d *Driver) api(ctx context.Context, method, path string, body any) ([]byte, int, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://"+apiAddr+path, reader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+d.secret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return data, resp.StatusCode, err
}

func (d *Driver) apiReady(ctx context.Context) bool {
	data, status, err := d.api(ctx, http.MethodGet, "/version", nil)
	return err == nil && status == http.StatusOK && bytes.Contains(data, []byte("version"))
}

// Apply implements engine.Driver: today's app rewrites the rule files, which
// sing-box reloads by itself; an IPv6 change restarts the engine.
func (d *Driver) Apply(ctx context.Context, p engine.Policy) error {
	d.mu.Lock()
	if !d.running() {
		d.mu.Unlock()
		return errors.New("sing-box isn't running")
	}
	if p.IPv6 != d.cfg.Policy.IPv6 {
		cfg, env, lanes := d.cfg, d.env, d.lanes
		cfg.Policy = p
		cfg.Lanes = lanes
		d.mu.Unlock()
		if err := d.Stop(ctx); err != nil {
			return err
		}
		return d.Start(ctx, env, cfg)
	}
	defer d.mu.Unlock()
	if err := d.generate(ctx, p, true, nil); err != nil {
		return err
	}
	d.cfg.Policy = p
	select {
	case <-time.After(ruleSettle):
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// SetLanes implements engine.Driver through the lanes' selectors.
func (d *Driver) SetLanes(ctx context.Context, lanes map[engine.LineID]engine.LineID) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.setLanes(ctx, lanes)
}

func (d *Driver) setLanes(ctx context.Context, lanes map[engine.LineID]engine.LineID) error {
	ids := make([]engine.LineID, 0, len(lanes))
	for lane := range lanes {
		ids = append(ids, lane)
	}
	slices.Sort(ids)
	for _, lane := range ids {
		target := lanes[lane]
		_, status, err := d.api(ctx, http.MethodPut, "/proxies/"+laneSelector(lane), map[string]string{"name": lineOutbound(target)})
		if err != nil {
			return fmt.Errorf("point lane %s at %s: %w", lane, target, err)
		}
		if status != http.StatusNoContent && status != http.StatusOK {
			return fmt.Errorf("point lane %s at %s: HTTP %d", lane, target, status)
		}
		d.lanes[lane] = target
	}
	return nil
}

// Flows implements engine.Driver.
func (d *Driver) Flows(ctx context.Context) ([]engine.Flow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.flows(ctx)
}

func (d *Driver) flows(ctx context.Context) ([]engine.Flow, error) {
	data, status, err := d.api(ctx, http.MethodGet, "/connections", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("/connections: HTTP %d", status)
	}
	return ParseConnections(data)
}

// CloseFlows implements engine.Driver: today's app closes connections one by
// one through the Clash API.
func (d *Driver) CloseFlows(ctx context.Context, sel engine.Selector) (engine.CloseResult, error) {
	var res engine.CloseResult
	if sel.Empty() {
		return res, errors.New("an empty selector is rejected")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	flows, err := d.flows(ctx)
	if err != nil {
		return res, err
	}
	for _, f := range flows {
		if !Matches(sel, f) {
			continue
		}
		_, status, err := d.api(ctx, http.MethodDelete, "/connections/"+f.ID, nil)
		switch {
		case err != nil:
			res.Failed++
		case status == http.StatusNotFound:
			res.Gone++
		case status/100 == 2:
			res.Closed++
		default:
			res.Failed++
		}
	}
	return res, nil
}

// Stop implements engine.Driver: SIGTERM, as the app stops it, then what
// this driver added around it goes.
func (d *Driver) Stop(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	var stopErr error
	if d.running() {
		_ = d.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-d.done:
		case <-time.After(5 * time.Second):
			d.kill()
			stopErr = errors.New("sing-box didn't stop within 5 s of SIGTERM and was killed")
		}
	}
	d.closeLog()
	return errors.Join(stopErr, d.removeOwn(ctx))
}

func (d *Driver) kill() {
	if d.cmd != nil && d.cmd.Process != nil {
		_ = d.cmd.Process.Kill()
	}
	if d.done != nil {
		select {
		case <-d.done:
		case <-time.After(5 * time.Second):
		}
	}
}

func (d *Driver) closeLog() {
	if d.logFile != nil {
		d.logFile.Close()
		d.logFile = nil
	}
}

// Crash implements engine.Driver.
func (d *Driver) Crash() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.running() {
		return errors.New("sing-box isn't running")
	}
	d.kill()
	d.closeLog()
	if d.running() {
		return errors.New("sing-box survived SIGKILL")
	}
	return nil
}

// Cleanup implements engine.Driver: what Net Switch on Linux would run after
// a crash. It deletes exactly what was recorded at start (the rules sing-box
// added, then ours), never anything by priority or table number alone.
func (d *Driver) Cleanup(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.running() {
		return errors.New("refusing to clean up after a running engine")
	}
	var errs []error
	now, err := d.rules(ctx)
	if err != nil {
		return err
	}
	for family, lines := range d.engineRules {
		for _, line := range lines {
			// A rule's identity is its fields; the kernel adds status flags such
			// as [detached] once the TUN it names is gone.
			if !slices.ContainsFunc(now[family], func(l string) bool { return RuleFingerprint(l) == RuleFingerprint(line) }) {
				continue
			}
			args, err := ruleDelArgs(family, line)
			if err == nil {
				_, err = d.ip(ctx, args...)
			}
			if err != nil {
				errs = append(errs, err)
			} else {
				d.logf("cleanup removed sing-box rule %q", line)
			}
		}
	}
	d.engineRules = nil
	errs = append(errs, d.removeOwn(ctx))
	if _, err := d.ip(ctx, "link", "show", tunName); err == nil {
		out, _ := d.ip(ctx, "-d", "link", "show", tunName)
		if strings.Contains(out, "tun") {
			_, err := d.ip(ctx, "link", "del", tunName)
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// rules reads `ip rule show` for both families.
func (d *Driver) rules(ctx context.Context) (map[string][]string, error) {
	out := map[string][]string{}
	for _, family := range []string{"-4", "-6"} {
		text, err := d.ip(ctx, family, "rule", "show")
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(text, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				out[family] = append(out[family], line)
			}
		}
	}
	return out, nil
}

// ruleDelArgs turns an `ip rule show` line ("31100:\tfrom all lookup 3110")
// into the `ip rule del` that removes exactly that rule.
func ruleDelArgs(family, line string) ([]string, error) {
	pref, rest, ok := strings.Cut(RuleFingerprint(line), ": ")
	if !ok {
		return nil, fmt.Errorf("can't read rule %q", line)
	}
	if _, err := strconv.Atoi(pref); err != nil {
		return nil, fmt.Errorf("can't read rule %q", line)
	}
	return append([]string{family, "rule", "del", "pref", pref}, strings.Fields(rest)...), nil
}

func (d *Driver) ownRule(family, line string) bool {
	pref, _, _ := strings.Cut(line, ":")
	n, _ := strconv.Atoi(strings.TrimSpace(pref))
	return n == localRulePref || n == sourceRulePref
}

// addOwn runs an `ip ... add` and records it for removal.
func (d *Driver) addOwn(ctx context.Context, args ...string) error {
	if _, err := d.ip(ctx, args...); err != nil {
		return err
	}
	d.own = append(d.own, args)
	return nil
}

// removeOwn removes what addOwn added: rules first, then routes, newest first.
func (d *Driver) removeOwn(ctx context.Context) error {
	var errs []error
	for _, kind := range []string{"rule", "route"} {
		for i := len(d.own) - 1; i >= 0; i-- {
			args := d.own[i]
			if !slices.Contains(args, kind) {
				continue
			}
			del := slices.Clone(args)
			for j, a := range del {
				if a == "add" {
					del[j] = "del"
					break
				}
			}
			if _, err := d.ip(ctx, del...); err != nil && !strings.Contains(err.Error(), "No such") && !strings.Contains(err.Error(), "Cannot find") {
				errs = append(errs, err)
			}
		}
	}
	d.own = nil
	return errors.Join(errs...)
}

type ipAddr struct {
	AddrInfo []struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
		Scope     string `json:"scope"`
	} `json:"addr_info"`
}

type ipRoute struct {
	Gateway string `json:"gateway"`
}

// addLinuxRouting adds the spike's Linux routing around sing-box.
func (d *Driver) addLinuxRouting(ctx context.Context) error {
	d.own = nil
	for i, l := range d.cfg.Lines {
		table := strconv.Itoa(lineTableBase + i + 1)
		for _, family := range []string{"-4", "-6"} {
			text, err := d.ip(ctx, "-j", family, "addr", "show", "dev", l.Interface)
			if err != nil {
				return err
			}
			var links []ipAddr
			if err := json.Unmarshal([]byte(text), &links); err != nil {
				return fmt.Errorf("ip -j addr: %w", err)
			}
			var gateway string
			if text, err := d.ip(ctx, "-j", family, "route", "show", "default", "dev", l.Interface); err == nil {
				var routes []ipRoute
				if json.Unmarshal([]byte(text), &routes) == nil && len(routes) > 0 {
					gateway = routes[0].Gateway
				}
			}
			var locals []string
			for _, link := range links {
				for _, info := range link.AddrInfo {
					if info.Scope != "global" {
						continue
					}
					addr, err := netip.ParseAddr(info.Local)
					if err != nil {
						continue
					}
					subnet := netip.PrefixFrom(addr, info.PrefixLen).Masked()
					if err := d.addOwn(ctx, family, "route", "add", subnet.String(), "dev", l.Interface, "src", addr.String(), "table", table); err != nil {
						return err
					}
					locals = append(locals, addr.String())
				}
			}
			if gateway != "" {
				if err := d.addOwn(ctx, family, "route", "add", "default", "via", gateway, "dev", l.Interface, "table", table); err != nil {
					return err
				}
			}
			for _, local := range locals {
				if err := d.addOwn(ctx, family, "rule", "add", "from", local, "lookup", table, "pref", strconv.Itoa(sourceRulePref)); err != nil {
					return err
				}
			}
		}
	}
	for _, r := range localRanges {
		family := "-4"
		if strings.Contains(r, ":") {
			family = "-6"
		}
		if err := d.addOwn(ctx, family, "rule", "add", "to", r, "lookup", "main", "pref", strconv.Itoa(localRulePref)); err != nil {
			return err
		}
	}
	return nil
}

// bridges lists bridge interfaces (container and VM networks) to exclude.
func (d *Driver) bridges(ctx context.Context) ([]string, error) {
	text, err := d.ip(ctx, "-j", "link", "show", "type", "bridge")
	if err != nil {
		return nil, err
	}
	var links []struct {
		Name string `json:"ifname"`
	}
	if err := json.Unmarshal([]byte(text), &links); err != nil {
		return nil, fmt.Errorf("ip -j link: %w", err)
	}
	var names []string
	for _, l := range links {
		names = append(names, l.Name)
	}
	return names, nil
}
