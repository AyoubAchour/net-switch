// Package nsengine drives netswitch-engine, Net Switch 1.0's own engine,
// through its control protocol (internal/engine/protocol, SYSTEM-DESIGN.md
// section 5.10).
//
// The protocol side is real: requests, replies, revisions, flows, totals,
// stats and refusals are main's own types, and nsengine_test.go runs every
// session operation against an in-memory protocol.Server. What's a stub is
// the engine process: netswitch-engine only answers "version" so far, so
// Prepare, Start and the process operations return engine.ErrNotImplemented,
// which the harness reports as an error. A run against this driver can never
// pass by accident.
//
// What the driver still needs from the engine, in the order cases use it:
//
//  1. A way to run outside systemd in a test namespace: for example
//     `netswitch-engine run --socket <path> --state-dir <dir>`, with the
//     journal (3.3) in the state dir and the socket mode 0600. The driver
//     runs it with `ip netns exec`, as it does sing-box, and connects a
//     Transport to the socket (JSON lines, as protocol.Serve reads them).
//  2. Refusal codes on the wire. A refusal arrives as its error text only, so
//     refusals.go classifies the texts, pinned to the real server by a test.
//     A code field in protocol.Reply would replace that table.
//  3. Test hooks, only in test builds, acknowledged when active: the
//     "udp-destroy-notifications" fault (engine.Fault), and the hooks the
//     pending overload gates name (suite/overload.go).
//  4. Cleanup after a crash: `netswitchctl cleanup --engine --state-dir <dir>`
//     reading the same journal, as ExecStopPost runs it.
package nsengine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/tests/linux/engine"
	"github.com/AyoubAchour/net-switch/tests/linux/harness"
)

// Transport carries one control request to the engine and returns the
// engine's reply to it, as the JSON line the engine wrote.
type Transport func(ctx context.Context, req protocol.Request) ([]byte, error)

// Driver is the netswitch-engine driver.
type Driver struct {
	exe harness.Executable
	// call reaches the engine's control socket; nil until the engine serves
	// one, and every protocol operation then fails as not implemented.
	call Transport
	// addresses reads a line's addresses from its interface: revisions carry
	// them (platform.Line).
	addresses func(ctx context.Context, netns, iface string) ([]netip.Addr, error)
	ops       atomic.Uint64

	mu      sync.Mutex
	env     engine.Env
	cfg     engine.Config
	n       uint64 // the last revision number sent
	session *Session
}

// New makes the driver for the engine binary at path.
func New(path string) *Driver {
	return &Driver{exe: harness.Executable{Role: "engine", Name: "netswitch-engine", Path: path}, addresses: lineAddresses}
}

var _ engine.V1 = (*Driver)(nil)

func notYet(op string) error {
	return fmt.Errorf("netswitch-engine %s: %w (the engine binary doesn't serve its control protocol yet)", op, engine.ErrNotImplemented)
}

// Executable implements engine.Driver.
func (d *Driver) Executable() harness.Executable { return d.exe }

// Kind implements engine.Driver.
func (d *Driver) Kind() harness.EngineKind { return harness.V1 }

// Prepare records the binary's version and hash, then reports that the
// engine can't run cases yet.
func (d *Driver) Prepare(ctx context.Context) error {
	if _, err := os.Stat(d.exe.Path); err != nil {
		return err
	}
	sum, err := harness.FileSHA256(d.exe.Path)
	if err != nil {
		return err
	}
	d.exe.SHA256 = sum
	out, err := exec.CommandContext(ctx, d.exe.Path, "version").Output()
	if err != nil {
		return fmt.Errorf("netswitch-engine version: %w", err)
	}
	d.exe.Version = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "netswitch-engine"))
	return notYet("run (a test namespace needs `netswitch-engine run --socket --state-dir`)")
}

// launch starts the engine in env's namespace and connects d.call to its
// control socket.
func (d *Driver) launch(context.Context, engine.Env) error {
	return notYet("run")
}

// Start implements engine.Driver: launch, attach, then revision 1.
func (d *Driver) Start(ctx context.Context, env engine.Env, cfg engine.Config) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.launch(ctx, env); err != nil {
		return err
	}
	d.env, d.cfg, d.n = env, cfg, 0
	s, err := d.attach(ctx)
	if err != nil {
		return err
	}
	d.session = s
	d.n = 1
	if _, err := s.Start(ctx, d.n, cfg); err != nil {
		return err
	}
	s.SetAutoRenew(true)
	return nil
}

// Apply implements engine.Driver: the next revision, with the new policy.
func (d *Driver) Apply(ctx context.Context, p engine.Policy) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	cfg := d.cfg
	cfg.Policy = p
	return d.next(ctx, cfg)
}

// SetLanes implements engine.Driver: lanes are part of the revision.
func (d *Driver) SetLanes(ctx context.Context, lanes map[engine.LineID]engine.LineID) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	cfg := d.cfg
	cfg.Lanes = map[engine.LineID]engine.LineID{}
	for lane, target := range d.cfg.Lanes {
		cfg.Lanes[lane] = target
	}
	for lane, target := range lanes {
		cfg.Lanes[lane] = target
	}
	return d.next(ctx, cfg)
}

func (d *Driver) next(ctx context.Context, cfg engine.Config) error {
	if d.session == nil {
		return notYet("apply")
	}
	// A case may have sent revisions through a session itself: continue
	// from the one in effect.
	h, err := d.Hello(ctx)
	if err != nil {
		return err
	}
	if h.Applied != nil && h.Applied.N > d.n {
		d.n = h.Applied.N
	}
	if _, err := d.session.Apply(ctx, d.n+1, cfg); err != nil {
		return err
	}
	d.n++
	d.cfg = cfg
	return nil
}

// Flows implements engine.Driver: every page of one snapshot.
func (d *Driver) Flows(ctx context.Context) ([]engine.Flow, error) {
	s := d.Session()
	if s == nil {
		return nil, notYet("flows")
	}
	var all []engine.Flow
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > 2048 {
			return nil, fmt.Errorf("flows: the cursor never ended after %d pages", pages)
		}
		page, err := s.Flows(ctx, cursor)
		if err != nil {
			return nil, err
		}
		all = append(all, page.Flows...)
		if page.Next == "" {
			return all, nil
		}
		if page.Next == cursor {
			return nil, fmt.Errorf("flows: the cursor didn't move (%q)", cursor)
		}
		cursor = page.Next
	}
}

// CloseFlows implements engine.Driver.
func (d *Driver) CloseFlows(ctx context.Context, sel engine.Selector) (engine.CloseResult, error) {
	s := d.Session()
	if s == nil {
		return engine.CloseResult{}, notYet("closeFlows")
	}
	return s.CloseFlows(ctx, fmt.Sprintf("driver-close-%d", d.ops.Add(1)), sel, 0)
}

// Stop implements engine.Driver.
func (d *Driver) Stop(ctx context.Context) error {
	s := d.Session()
	if s == nil {
		return notYet("stop")
	}
	s.SetAutoRenew(false)
	if err := s.Stop(ctx); err != nil {
		return err
	}
	return d.WaitExit(ctx)
}

// Crash implements engine.Driver.
func (d *Driver) Crash() error { return notYet("crash") }

// Cleanup implements engine.Driver.
func (d *Driver) Cleanup(context.Context) error { return notYet("cleanup") }

// Running implements engine.Driver.
func (d *Driver) Running() bool { return false }

// LogPath implements engine.Driver.
func (d *Driver) LogPath() string { return "" }

// Hello implements engine.V1.
func (d *Driver) Hello(ctx context.Context) (engine.Hello, error) {
	var h struct {
		Version      string          `json:"version"`
		Instance     string          `json:"engineInstanceId"`
		Applied      *policy.Applied `json:"appliedRevision"`
		Epoch        uint64          `json:"epoch"`
		Capabilities []string        `json:"capabilities"`
	}
	if err := d.do(ctx, protocol.Request{ID: d.id("hello"), Method: "hello"}, &h); err != nil {
		return engine.Hello{}, err
	}
	out := engine.Hello{Version: h.Version, InstanceID: h.Instance, Epoch: h.Epoch, Capabilities: h.Capabilities}
	if h.Applied != nil {
		a := applied(*h.Applied)
		out.Applied = &a
	}
	return out, nil
}

// Attach implements engine.V1: the engine hands out the session's epoch.
func (d *Driver) Attach(ctx context.Context) (engine.Controller, error) {
	s, err := d.attach(ctx)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (d *Driver) attach(ctx context.Context) (*Session, error) {
	h, err := d.Hello(ctx)
	if err != nil {
		return nil, err
	}
	// Epoch 0: Control never picks one (5.9).
	var lease struct {
		Epoch        uint64 `json:"epoch"`
		LeaseSeconds int    `json:"leaseSeconds"`
	}
	if err := d.do(ctx, protocol.Request{ID: d.id("attach"), Method: "attach", Instance: h.InstanceID}, &lease); err != nil {
		return nil, err
	}
	if lease.Epoch == 0 {
		return nil, fmt.Errorf("attach: the engine handed out epoch 0")
	}
	return &Session{d: d, instance: h.InstanceID, epoch: lease.Epoch}, nil
}

// Session implements engine.V1.
func (d *Driver) Session() engine.Controller {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.session == nil {
		return nil
	}
	return d.session
}

// WaitExit implements engine.V1.
func (d *Driver) WaitExit(context.Context) error { return notYet("wait for exit") }

func (d *Driver) id(method string) string {
	return fmt.Sprintf("%s-%d", method, d.ops.Add(1))
}

// reply is protocol.Reply with its result left for the caller to decode.
type reply struct {
	ID     string          `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// do sends one request and decodes its result into out (nil: ignore it). A
// refusal comes back as an *engine.Refusal; anything else the engine reports
// is a plain error.
func (d *Driver) do(ctx context.Context, req protocol.Request, out any) error {
	if d.call == nil {
		return notYet(req.Method)
	}
	line, err := d.call(ctx, req)
	if err != nil {
		return fmt.Errorf("%s: %w", req.Method, err)
	}
	var rep reply
	if err := json.Unmarshal(line, &rep); err != nil {
		return fmt.Errorf("%s: unreadable reply %q: %w", req.Method, truncate(line), err)
	}
	if rep.ID != req.ID {
		return fmt.Errorf("%s: the reply is for request %q, not %q", req.Method, rep.ID, req.ID)
	}
	if rep.Error != "" {
		return fmt.Errorf("%s: %w", req.Method, classify(rep.Error))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(rep.Result, out); err != nil {
		return fmt.Errorf("%s: unexpected result %q: %w", req.Method, truncate(rep.Result), err)
	}
	return nil
}

func truncate(b []byte) string {
	if len(b) > 200 {
		return string(b[:200]) + "..."
	}
	return string(b)
}
