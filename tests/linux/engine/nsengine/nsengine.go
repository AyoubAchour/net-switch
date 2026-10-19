// Package nsengine will drive netswitch-engine, Net Switch 1.0's own engine,
// through its control protocol (SYSTEM-DESIGN.md section 5.10). It's a stub:
// the engine binary only answers "version" so far, and the protocol isn't
// built yet. Every operation returns engine.ErrNotImplemented, which the
// harness reports as an error, so a run against this driver can never pass
// by accident.
//
// What the driver needs from the engine, in the order cases use it:
//
//  1. A way to run outside systemd in a test namespace: for example
//     `netswitch-engine run --socket <path> --state-dir <dir>`, with the
//     journal (3.3) in the state dir and the socket mode 0600. The driver
//     runs it with `ip netns exec`, as it does sing-box.
//  2. The control socket's framing and messages, with every refusal typed
//     (engine.Refusal codes: stale-revision, revision-conflict, fenced,
//     wrong-instance, lapsing, empty-selector):
//     - hello: version, instance id, capabilities, appliedRevision (history)
//     and the loaded revision (nil until start);
//     - attach, answered with the epoch the engine hands out (5.9), fencing
//     the previous session; renew; a 30 s lease, renewed every 5 s; every
//     command carrying {instanceId, epoch};
//     - start{revision} and apply{revision} with the caller's n and hash,
//     acknowledged with appliedRevision and the apply point;
//     - stop, graceful and idempotent.
//  3. A revision carrying everything engine.Config has: lines by interface
//     name in priority order, pins by identity (engine.App.Key: "snap:",
//     "flatpak:", "appimage:" or a path), combining shares, the blocked set,
//     IPv6, and lanes (and a way to point lanes alone).
//  4. flows{cursor} paged, each flow with id, epoch, start, app {path, id},
//     pid, protocol, source, destination, selected lane, physical line,
//     revision and bytes; totals per app and line including closed flows.
//  5. closeFlows{opId, selector, startedBefore} with the selectors in
//     engine.Selector, answering {closed, failed, gone}; repeating an opId
//     returns the recorded result.
//  6. probe{opId, line, operator} with a quick (TCP) kind; predict{app};
//     stats with a lookup-latency histogram (fixed buckets), lookup misses,
//     ambiguous owners and the combining counter k.
//  7. Test hooks, only in test builds, acknowledged when active: the
//     "udp-destroy-notifications" fault, dropping or delaying sock_diag UDP
//     destroy notifications (5.3).
//  8. Cleanup after a crash: `netswitchctl cleanup --engine --state-dir <dir>`
//     reading the same journal, as ExecStopPost runs it.
package nsengine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/AyoubAchour/net-switch/tests/linux/engine"
	"github.com/AyoubAchour/net-switch/tests/linux/harness"
)

// Driver is the netswitch-engine driver (a stub).
type Driver struct {
	exe harness.Executable
}

// New makes the driver for the engine binary at path.
func New(path string) *Driver {
	return &Driver{exe: harness.Executable{Role: "engine", Name: "netswitch-engine", Path: path}}
}

var _ engine.V1 = (*Driver)(nil)

func notYet(op string) error {
	return fmt.Errorf("netswitch-engine %s: %w (the driver waits for the engine's control protocol)", op, engine.ErrNotImplemented)
}

// Executable implements engine.Driver.
func (d *Driver) Executable() harness.Executable { return d.exe }

// Kind implements engine.Driver.
func (d *Driver) Kind() harness.EngineKind { return harness.V1 }

// Prepare records the binary's version and hash, then reports that the
// driver can't run cases yet.
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
	return notYet("control protocol")
}

// Start implements engine.Driver.
func (d *Driver) Start(context.Context, engine.Env, engine.Config) error { return notYet("start") }

// Apply implements engine.Driver.
func (d *Driver) Apply(context.Context, engine.Policy) error { return notYet("apply") }

// SetLanes implements engine.Driver.
func (d *Driver) SetLanes(context.Context, map[engine.LineID]engine.LineID) error {
	return notYet("lanes")
}

// Flows implements engine.Driver.
func (d *Driver) Flows(context.Context) ([]engine.Flow, error) { return nil, notYet("flows") }

// CloseFlows implements engine.Driver.
func (d *Driver) CloseFlows(context.Context, engine.Selector) (engine.CloseResult, error) {
	return engine.CloseResult{}, notYet("closeFlows")
}

// Stop implements engine.Driver.
func (d *Driver) Stop(context.Context) error { return notYet("stop") }

// Crash implements engine.Driver.
func (d *Driver) Crash() error { return notYet("crash") }

// Cleanup implements engine.Driver.
func (d *Driver) Cleanup(context.Context) error { return notYet("cleanup") }

// Running implements engine.Driver.
func (d *Driver) Running() bool { return false }

// LogPath implements engine.Driver.
func (d *Driver) LogPath() string { return "" }

// Hello implements engine.V1.
func (d *Driver) Hello(context.Context) (engine.Hello, error) { return engine.Hello{}, notYet("hello") }

// Attach implements engine.V1.
func (d *Driver) Attach(context.Context) (engine.Controller, error) { return nil, notYet("attach") }

// Session implements engine.V1; there's none until the protocol exists.
func (d *Driver) Session() engine.Controller { return nil }

// WaitExit implements engine.V1.
func (d *Driver) WaitExit(context.Context) error { return notYet("wait for exit") }
