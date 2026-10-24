package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apppath"
	"github.com/AyoubAchour/net-switch/internal/apps"
	ce "github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/host"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/internal/service"
)

// The native engine speaks spec §5.10 directly: revisions carry the compiled
// policy.Config, flows are paged records, probes name a target and kind, and
// accounting is paged and acknowledged. The temporary adapter dialect stays
// selectable from the hello capabilities until the removal PR deletes it.
var nativeRequired = []string{"revisions", "lease", "status", "paged-totals", "totals-ack", "terminal-stop", "probe-options"}

// adapterLostPendingBound caps how long Control waits for the stopped engine's
// cleanup result before classifying its exit. Pending past this bound counts
// as an ordinary failure and is logged: it is never guessed to be clean.
const adapterLostPendingBound = 10 * time.Second

func nativeDialect(capabilities []string) (adapter bool, err error) {
	have := map[string]bool{}
	for _, v := range capabilities {
		have[v] = true
	}
	if have["singbox-adapter-v1"] {
		return true, nil
	}
	for _, v := range nativeRequired {
		if !have[v] {
			return false, fmt.Errorf("engine lacks the %q capability Control requires", v)
		}
	}
	return false, nil
}

// appIdentityRules are the engine's own path normalisation for this OS: the
// Windows owner lookup keys apps by apppath.Key (Windows rules), the Linux one
// by apppath.Normalize with Linux rules, which keeps case and separators.
var appIdentityRules = func() apppath.Rules {
	if runtime.GOOS == "linux" {
		return apppath.Linux
	}
	return apppath.Windows
}()

// engineAppIdentity is the identity the engine gives a plain executable.
func engineAppIdentity(path string) string { return engineAppIdentityWith(path, appIdentityRules) }
func engineAppIdentityWith(path string, rules apppath.Rules) string {
	if path == "" {
		return ""
	}
	return apppath.Normalize(path, rules)
}

// pinIdentity is the engine identity a pin binds (design decision recorded in
// the spec): the exact identity the user selected, never inferred from a path
// other apps may share. A Windows path pin is the normalised path, which is
// also the Windows engine's identity, so existing pins stay valid. On Linux a
// path pin inside a sandbox location cannot name the app the person meant (the
// engine reports it by sandbox identity), so it compiles to nothing and is
// shown as needing reselection rather than routed by guess.
func pinIdentity(value string, rules apppath.Rules) (string, bool) {
	if apps.SandboxIdentity(value) {
		return value, true
	}
	if rules.Separator == "/" && apps.PinNeedsReselection(apps.Pin{Path: value}, "") {
		return "", false
	}
	return engineAppIdentityWith(value, rules), true
}

// nativeRevision compiles Control's policy into the engine's config. The line
// binds by alias, the same identity the sing-box adapter used, so the config
// is a pure function of Control's durable revision alone: the same revision
// compiles to the same hash after any restart, and an alias change still goes
// through Control's existing restart rule.
func nativeRevision(r ce.Revision) (policy.Revision, error) {
	return nativeRevisionWith(r, appIdentityRules)
}
func nativeRevisionWith(r ce.Revision, rules apppath.Rules) (policy.Revision, error) {
	p := r.Policy
	config := policy.Config{Combine: p.Combine, IPv6: p.IPv6, AppLines: map[string]string{}, Shares: map[string]uint64{}, Lanes: map[string]string{}, Blocked: []string{}}
	known := map[string]bool{}
	for _, line := range p.Lines {
		if line.ID == "" || line.Alias == "" {
			return policy.Revision{}, fmt.Errorf("line %q has no interface alias", line.ID)
		}
		known[line.ID] = true
		config.Lines = append(config.Lines, platform.Line{ID: line.ID, Interface: line.Alias})
	}
	for _, pin := range p.AppLines {
		if !known[pin.LineID] || pin.Path == "" {
			continue
		}
		if id, ok := pinIdentity(pin.Path, rules); ok {
			config.AppLines[id] = pin.LineID
		}
	}
	blocked := map[string]bool{}
	for _, id := range p.Blocked {
		if known[id] && !blocked[id] {
			blocked[id] = true
			config.Blocked = append(config.Blocked, id)
		}
	}
	// Control shares only open lines (spec §4.6), so a blocked line never has
	// a share; the engine refuses one, so the translation drops it as well.
	for _, share := range p.Shares {
		if known[share.ID] && !blocked[share.ID] && share.Value > 0 && !math.IsNaN(share.Value) && !math.IsInf(share.Value, 0) {
			config.Shares[share.ID] = uint64(math.Round(share.Value * 1_000_000))
		}
	}
	for id, target := range p.Lanes {
		if known[id] && known[target] {
			config.Lanes[id] = target
		}
	}
	if r.Number == 0 {
		return policy.Revision{}, errors.New("revision number is required")
	}
	return policy.Revision{N: r.Number, Hash: policy.Hash(config), Config: config}, nil
}

// nativeStatus turns the engine's fixed-size status into Control's snapshot.
// Policy fields come from Control's own durable revision when the engine has
// loaded exactly that revision; otherwise Control re-sends it.
func (r *Remote) nativeSnapshotLocked(status protocol.Status) ce.Snapshot {
	s := ce.Snapshot{Status: status.State, Instance: status.Instance, PID: status.PID, StartedAt: status.Started}
	if s.Status == "" {
		s.Status = "off"
	}
	if s.Status == "error" && status.LastError != "" {
		message := status.LastError
		s.Error = &message
		s.FailureID = status.Instance
	}
	if status.Applied != nil {
		s.AppliedRevision, s.AppliedHash, s.AppliedPoint = status.Applied.N, status.Applied.Hash, status.Applied.Point
		if desired := r.desired; desired != nil && desired.Number == status.Applied.N {
			if native, err := nativeRevision(*desired); err == nil && native.Hash == status.Applied.Hash {
				s.AppliedHash = desired.Hash
				s.Policy = desired.Policy
				if s.Status == "on" {
					loaded := desired.Policy
					s.StartedWith = &loaded
				}
			}
		}
	}
	return s
}

func (r *Remote) nativeRefresh(ctx context.Context) error {
	r.mu.Lock()
	rpc, instance := r.rpc, r.instance
	r.mu.Unlock()
	var status protocol.Status
	if err := r.call(ctx, "status", nil, "", &status); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rpc == rpc && r.instance == instance && !r.stopping {
		s := r.nativeSnapshotLocked(status)
		s.Instance = instance
		r.snapshot = s
	}
	return nil
}

// nativeLoad sends start or apply. An engine that is already on receives apply,
// which the table answers idempotently; start is only for a fresh instance.
func (r *Remote) nativeLoad(ctx context.Context, revision ce.Revision, running bool) (ce.Acknowledgement, error) {
	native, err := nativeRevision(revision)
	if err != nil {
		return ce.Acknowledgement{}, err
	}
	method := "start"
	if running {
		method = "apply"
	}
	var applied policy.Applied
	if err := r.call(ctx, method, map[string]any{"revision": native}, "", &applied); err != nil {
		return ce.Acknowledgement{}, err
	}
	if applied.N != native.N || applied.Hash != native.Hash {
		return ce.Acknowledgement{}, errors.New("engine acknowledged a different revision")
	}
	r.mu.Lock()
	instance := r.instance
	r.mu.Unlock()
	return ce.Acknowledgement{Number: revision.Number, Hash: revision.Hash, Instance: instance, Point: applied.Point}, nil
}

func (r *Remote) nativeConnections(ctx context.Context) ([]ce.Connection, error) {
	out := []ce.Connection{}
	cursor := ""
	seen := map[string]bool{}
	for {
		var page flows.Page
		fields := map[string]any{}
		if cursor != "" {
			fields["cursor"] = cursor
		}
		if err := r.call(ctx, "flows", fields, "", &page); err != nil {
			return nil, err
		}
		for _, f := range page.Flows {
			out = append(out, nativeConnection(f))
		}
		if len(out) > flows.Defaults().SnapshotEntries {
			return nil, errors.New("engine flow snapshot exceeds its entry limit")
		}
		if page.Cursor == "" {
			return out, nil
		}
		if seen[page.Cursor] || len(page.Flows) == 0 {
			return nil, errors.New("engine flow cursor made no progress")
		}
		seen[page.Cursor] = true
		cursor = page.Cursor
	}
}

// nativeConnection keeps the Chains[0] = "line-<id>" shape every Control
// consumer reads (the tracker, lane counts, Reconnect selectors). Host is the
// destination address only once the upstream connection is established, so a
// flow still connecting is never evidence that its line works (spec §4.5).
func nativeConnection(f flows.Record) ce.Connection {
	c := ce.Connection{}
	c.ID = strconv.FormatUint(f.ID, 10)
	c.AppID = f.Owner.AppID
	c.Metadata.ProcessPath = f.Owner.Path
	c.Download, c.Upload = float64(f.Down), float64(f.Up)
	c.Start = f.Start.UTC().Format(time.RFC3339Nano)
	if f.Line != "" {
		c.Chains = []string{"line-" + f.Line}
	}
	if f.PhysicalSource.IsValid() && f.Destination.IsValid() {
		c.Host = f.Destination.Addr().Unmap().String()
	}
	return c
}

func (r *Remote) nativeClose(ctx context.Context, request ce.CloseRequest) (ce.CloseResult, error) {
	selector := flows.Selector{}
	fields := map[string]any{}
	if request.Line != "" {
		selector.Line = request.Line
		if request.StartedBeforePoint == 0 {
			return ce.CloseResult{}, errors.New("line closure requires its apply-point cutoff")
		}
		fields["startedBefore"] = request.StartedBeforePoint
	} else {
		for _, id := range request.ConnectionIDs {
			n, err := strconv.ParseUint(id, 10, 64)
			if err != nil {
				return ce.CloseResult{}, fmt.Errorf("flow id %q is not a native flow id", id)
			}
			selector.IDs = append(selector.IDs, n)
		}
		if len(selector.IDs) == 0 {
			return ce.CloseResult{}, errors.New("closure selects nothing")
		}
	}
	fields["selector"] = selector
	if request.Instance == "" {
		return ce.CloseResult{}, errors.New("closure names no engine instance")
	}
	// Flow ids are per instance and reused by a replacement. The closure is
	// bound to the instance Core checked, atomically with the session capture.
	var result flows.CloseResult
	err := r.fencedRequest(ctx, request.Instance, "closeFlows", fields, request.OperationID, "", &result)
	return ce.CloseResult{Closed: result.Closed, Failed: result.Failed, Gone: result.Gone}, err
}

func (r *Remote) nativeProbe(ctx context.Context, request ce.ProbeRequest) ce.ProbeResult {
	r.mu.Lock()
	instance := r.instance
	r.mu.Unlock()
	want := "full"
	if request.Quick {
		want = "quick"
	}
	out := ce.ProbeResult{Outcome: ce.Unavailable, Kind: want, Instance: instance}
	var result platform.ProbeResult
	fields := map[string]any{"line": request.Line, "target": request.Target, "quick": request.Quick, "custom": request.Custom}
	if err := r.call(ctx, "probe", fields, request.OperationID, &result); err != nil {
		return out
	}
	out.Kind = result.Kind
	switch result.Outcome {
	case "ok":
		out.Outcome = ce.OK
	case "lineFailed":
		out.Outcome = ce.LineFailed
	case "engineUnavailable", "":
		out.Outcome = ce.Unavailable
	default:
		out.Outcome = ce.Unavailable
	}
	if out.Outcome == ce.OK && result.LatencyMS != nil {
		delay := *result.LatencyMS
		out.Delay = &delay
	}
	return out
}

// Totals and AckTotals are spec §5.10's paged, acknowledged accounting.
func (r *Remote) Totals(ctx context.Context, cursor string) (ce.TotalsPage, error) {
	r.mu.Lock()
	native, instance := r.native, r.instance
	r.mu.Unlock()
	if !native {
		return ce.TotalsPage{}, ce.ErrNoAccounting
	}
	fields := map[string]any{}
	if cursor != "" {
		fields["cursor"] = cursor
	}
	var page flows.TotalsPage
	if err := r.call(ctx, "totals", fields, "", &page); err != nil {
		return ce.TotalsPage{}, err
	}
	if page.Instance != "" && page.Instance != instance {
		return ce.TotalsPage{}, errors.New("totals page belongs to another engine instance")
	}
	out := ce.TotalsPage{Instance: instance, Apps: map[string]ce.Counter{}, Lines: map[string]ce.Counter{}, Cursor: page.Cursor, Receipt: page.Receipt, Count: page.Count}
	for id, c := range page.Apps {
		out.Apps[id] = ce.Counter{Up: c.Up, Down: c.Down, Generation: c.Generation}
	}
	for id, c := range page.Lines {
		out.Lines[id] = ce.Counter{Up: c.Up, Down: c.Down, Generation: c.Generation}
	}
	return out, nil
}
func (r *Remote) AckTotals(ctx context.Context, opID, receipt string) error {
	r.mu.Lock()
	native := r.native
	r.mu.Unlock()
	if !native {
		return ce.ErrNoAccounting
	}
	var ack flows.TotalsAck
	return r.call(ctx, "ackTotals", map[string]any{"receipt": receipt}, opID, &ack)
}

// exitStopped is a verified clean stop: exit 0, cleanup complete, and the
// engine's own "stop" reason. It is routing off, never a failure.
const exitStopped = "stopped"

type exitClass struct {
	reason  string // "", "lease-expired", exitStopped or ce.ReasonAdapterLost
	pending bool
}

// classifyExit reads a stopped engine's outcome through the service manager
// and the shared outcome reader. Only a known exit 3 with completed cleanup is
// adapter loss; a lease expiry or a verified clean stop is routing off;
// anything else is a failure.
func (r *Remote) classifyExit(instance string, status service.Status) (exitClass, error) {
	r.mu.Lock()
	native := r.native
	r.mu.Unlock()
	// The service manager reports Cleanup only for a native installation, so
	// a retained native exit is classified natively even before any hello.
	native = native || status.Cleanup != ""
	if !native || r.outcome == nil {
		if r.exitReason == nil {
			return exitClass{}, nil
		}
		reason, err := r.exitReason(instance)
		return exitClass{reason: reason}, err
	}
	if instance == "" {
		return exitClass{}, nil
	}
	switch status.Cleanup {
	case "", "pending", "running":
		return exitClass{pending: true}, nil
	}
	out, err := r.outcome(instance)
	if err != nil {
		return exitClass{}, err
	}
	if out.Reason == "lease-expired" {
		return exitClass{reason: "lease-expired"}, nil
	}
	if status.Cleanup == "complete" && status.ExitKnown && status.ExitCode == 3 && out.Reason == "adapter lost" {
		return exitClass{reason: ce.ReasonAdapterLost}, nil
	}
	if status.Cleanup == "complete" && status.ExitKnown && status.ExitCode == 0 && out.Reason == "stop" && out.Error == "" {
		return exitClass{reason: exitStopped}, nil
	}
	return exitClass{}, nil
}

func describeExit(status service.Status) string {
	parts := []string{fmt.Sprintf("cleanup=%s", status.Cleanup)}
	if status.ExitKnown {
		parts = append(parts, fmt.Sprintf("exit=%d", status.ExitCode))
	}
	if status.LastError != "" {
		parts = append(parts, "error="+status.LastError)
	}
	return strings.Join(parts, " ")
}

// nativeOutcomeReader reads the stopped instance's outcome file through the
// sharing-safe reader every native outcome consumer uses.
func nativeOutcomeReader(data string) func(string) (host.Outcome, error) {
	return func(instance string) (host.Outcome, error) { return host.ReadOutcome(data, instance) }
}

// classifyRetainedExit runs at Control startup when no engine is attached. A
// native engine that failed or lost its adapter while Control was down is
// classified like a live exit, so it counts toward the budget (deduplicated
// by Core against the journal's last failure id) before any restart. A lease
// expiry or an engine never recorded leaves the snapshot off.
func (r *Remote) classifyRetainedExit(ctx context.Context, data string) error {
	record, err := host.ReadRecord(filepath.Join(data, "engine-state.json"))
	if os.IsNotExist(err) || (err == nil && record.Instance == "") {
		return nil
	}
	if err != nil {
		// Not a native record: the stand-in's exit reason file applies.
		return nil
	}
	pendingSince := time.Time{}
	for {
		status, err := r.queryService(service.Engine)
		if err != nil {
			return err
		}
		if !status.Stopped {
			return nil
		}
		class, err := r.classifyExit(record.Instance, status)
		if err != nil {
			return err
		}
		if class.pending {
			if pendingSince.IsZero() {
				pendingSince = time.Now()
			}
			if time.Since(pendingSince) < adapterLostPendingBound {
				if err := localipc.Pause(ctx, 500*time.Millisecond); err != nil {
					return err
				}
				continue
			}
			r.log(fmt.Sprintf("retained engine cleanup still pending after %s (%s); counting the exit as a failure", adapterLostPendingBound, describeExit(status)))
			class = exitClass{}
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		r.instance = record.Instance
		switch class.reason {
		case "lease-expired", exitStopped:
			// Off, not a failure: a deliberate stop before Control crashed, or
			// an expired lease. Resume follows the journaled routing intent.
			r.snapshot = ce.Snapshot{Status: "off"}
		case ce.ReasonAdapterLost:
			r.failWithReasonLocked(fmt.Errorf("adapter lost while Control was unavailable (%s)", describeExit(status)), ce.ReasonAdapterLost)
			r.snapshot.Instance = record.Instance
		default:
			r.failLocked(fmt.Errorf("engine instance failed while Control was unavailable (%s)", describeExit(status)))
			r.snapshot.Instance = record.Instance
		}
		return nil
	}
}

// acknowledgeTerminal answers the engine's service-initiated stop record on
// the connection that received it, so adapter-loss cleanup does not wait out
// the delivery timeout. It never changes routing intent.
func (r *Remote) acknowledgeTerminal(rpc *RPC, b []byte) {
	var message protocol.Terminal
	if json.Unmarshal(b, &message) != nil || message.Type != "stopped" || message.OpID == "" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(r.ctx, protocol.TerminalDeliveryTimeout)
		defer cancel()
		if err := rpc.Call(ctx, map[string]any{"method": "terminalAck", "engineInstanceId": message.Instance, "epoch": message.Epoch, "opId": message.OpID}, nil); err != nil {
			r.log("engine terminal receipt not delivered: " + err.Error())
		} else {
			r.log(fmt.Sprintf("engine stopped itself (%s); receipt sent", message.Reason))
		}
	}()
}
