// Package engine is the acceptance suite's view of a routing engine: the
// operations Net Switch's control service needs (SYSTEM-DESIGN.md section
// 5.10), without saying how an engine does them. Each engine under test has a
// driver:
//
//   - singbox: the baseline, sing-box as today's app configures it, plus the
//     Linux changes the feasibility spike found (LINUX-PLAN.md section 0).
//   - nsengine: netswitch-engine, 1.0's own engine (a stub until the engine
//     speaks its control protocol).
//
// The suite plays the control service: it picks lines, pins apps, points
// lanes and closes flows through a Driver, and judges the engine only by what
// apps and servers see, plus what the engine reports about its flows. V1 and
// Controller expose the parts of the protocol only 1.0 has, with every
// acknowledgement and refusal visible, so requires-1.0 cases can check them.
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/harness"
)

// ErrNotImplemented is returned by a driver that can't do an operation yet. The
// harness treats it as a harness error, so it never passes silently.
var ErrNotImplemented = errors.New("not implemented by this engine driver")

// LineID names a line: "a", "b", "c".
type LineID string

// Line is one internet connection, by the interface it's on in the engine's
// network namespace. The engine finds its addresses and gateways itself.
type Line struct {
	ID        LineID
	Interface string
}

// App names a program the way Net Switch pins it. Path is where its executable
// is seen (evidence); ID is its identity where it has one: "snap:<name>",
// "flatpak:<app id>" or "appimage:<registered name>". 1.0 matches on ID when
// set (section 5.4); an engine that only knows paths matches on Path.
type App struct {
	Path string
	ID   string
}

// Key is the identity 1.0 matches on.
func (a App) Key() string {
	if a.ID != "" {
		return a.ID
	}
	return a.Path
}

// Pin places an app on a line.
type Pin struct {
	App  App
	Line LineID
}

// Policy is what the control service decides: pins, combining, blocked lines
// and IPv6. It's applied whole.
type Policy struct {
	Pins    []Pin
	Combine bool
	// Shares are the combining weights of the lines taking part, summing to 1.
	Shares map[LineID]float64
	// Blocked lines are out of data: apps pinned to them are refused (4.6).
	Blocked []LineID
	IPv6    bool
}

// Profile picks between configurations of the same engine.
type Profile string

const (
	// ProfileLinux is the engine as it should run on Linux. The default.
	ProfileLinux Profile = ""
	// ProfileProduct is the baseline exactly as today's app generates its
	// config, without the spike's Linux changes. Only the baseline differs;
	// 1.0 has one configuration.
	ProfileProduct Profile = "product"
)

// Config is a complete start: everything the engine needs before capturing.
type Config struct {
	Lines  []Line // priority order, the main line first
	Policy Policy
	// Lanes points a line's lane at another line (failover); a line missing
	// here points at itself.
	Lanes   map[LineID]LineID
	Profile Profile
}

// Flow is one connection or UDP session as the engine reports it.
type Flow struct {
	ID          string
	App         string // executable path, without decorations such as " (deleted)"
	AppID       string // identity, where the engine reports one (1.0)
	PID         int    // 0 when the engine doesn't report it
	Protocol    string // "tcp", "udp" or "icmp"
	Source      netip.AddrPort
	Destination netip.AddrPort
	Lane        LineID // the lane (selector) it was decided by
	Line        LineID // the physical line carrying it
	Revision    int64  // the policy revision it was admitted under (1.0)
	Epoch       uint64 // the engine epoch it was admitted in (1.0)
	Started     time.Time
	Up, Down    int64
}

// Selector picks flows to close. Exactly one form is used: IDs; Line; or App
// with NotLine (Reconnect: the app's flows not on that line).
type Selector struct {
	IDs     []string
	Line    LineID
	App     string
	NotLine LineID
}

// Empty reports whether the selector would match nothing on purpose; the
// protocol rejects it (5.10).
func (s Selector) Empty() bool {
	return len(s.IDs) == 0 && s.Line == "" && s.App == ""
}

// CloseResult is closeFlows' answer.
type CloseResult struct {
	Closed, Failed, Gone int
}

// Env is where a driver runs its engine.
type Env struct {
	// Netns is the network namespace standing in for the PC.
	Netns string
	// WorkDir holds the engine's config, state and log for this case.
	WorkDir string
	// Logf goes to the case log.
	Logf func(format string, args ...any)
}

// Driver controls one engine under test, the way the control service does.
type Driver interface {
	// Executable is the program under test; Prepare fills in its version and
	// SHA-256.
	Executable() harness.Executable
	Kind() harness.EngineKind
	// Prepare checks the program before any case runs.
	Prepare(ctx context.Context) error

	// Start runs the engine with a complete config and returns once it's
	// capturing traffic.
	Start(ctx context.Context, env Env, cfg Config) error
	// Apply replaces the policy and returns once it's in effect.
	Apply(ctx context.Context, p Policy) error
	// SetLanes points each given line's lane at a target line. Existing flows
	// keep their line (5.4).
	SetLanes(ctx context.Context, lanes map[LineID]LineID) error
	// Flows lists all open flows.
	Flows(ctx context.Context) ([]Flow, error)
	// CloseFlows closes the selected flows.
	CloseFlows(ctx context.Context, sel Selector) (CloseResult, error)
	// Stop stops the engine gracefully; it cleans up after itself.
	Stop(ctx context.Context) error
	// Crash kills the engine without letting it clean up.
	Crash() error
	// Cleanup is what runs after a crash without a restart (Linux:
	// ExecStopPost=netswitchctl cleanup --engine). It must remove what the
	// engine created and nothing else.
	Cleanup(ctx context.Context) error
	// Running reports whether the engine process is alive.
	Running() bool
	// LogPath is the engine's log for this case.
	LogPath() string
}

// Revision identifies a policy revision. Control picks n and the hash and
// persists both before sending (3.3).
type Revision struct {
	N    int64
	Hash string
}

// RevisionHash is the hash a control service would give cfg: SHA-256 of its
// JSON (Go encodes map keys in order, so it's stable).
func RevisionHash(cfg Config) string {
	data, err := json.Marshal(cfg)
	if err != nil {
		panic(err) // Config has only plain fields
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Ack is the engine's acknowledgement of start or apply.
type Ack struct {
	Applied Revision
	// ApplyPoint marks when the revision took effect in this engine
	// instance; closeFlows' startedBefore takes it.
	ApplyPoint uint64
}

// Refusal codes the protocol defines (2, 3.3, 5.10).
const (
	RefusedStale         = "stale-revision"    // a lower n than the loaded one
	RefusedConflict      = "revision-conflict" // the same n with another hash
	RefusedFenced        = "fenced"            // a newer controller attached
	RefusedWrongInstance = "wrong-instance"    // the command named another engine instance
	RefusedLapsing       = "lapsing"           // lease-lapse cleanup has begun
	RefusedEmptySelector = "empty-selector"
)

// Refusal is a refusal the protocol defines, as opposed to a failure.
type Refusal struct {
	Code    string
	Message string
}

func (r *Refusal) Error() string { return fmt.Sprintf("refused (%s): %s", r.Code, r.Message) }

// RefusedWith reports whether err is the protocol refusal code.
func RefusedWith(err error, code string) bool {
	var r *Refusal
	return errors.As(err, &r) && r.Code == code
}

// Hello is the engine's greeting (5.10).
type Hello struct {
	Version      string
	InstanceID   string
	Capabilities []string
	// AppliedRevision is the last revision the engine persisted: history only
	// after a restart (3.3).
	AppliedRevision *Revision
	// LoadedRevision is the revision in effect now: nil until start.
	LoadedRevision *Revision
}

// FlowPage is one page of flows{cursor}; Next is "" on the last page.
type FlowPage struct {
	Flows []Flow
	Next  string
}

// Bytes are cumulative byte counts.
type Bytes struct {
	Up, Down int64
}

// Totals are cumulative bytes per app key and per line, including flows
// closed since the last poll (5.10).
type Totals struct {
	PerApp  map[string]Bytes
	PerLine map[LineID]Bytes
}

// ProbeResult is probe's answer (4.5).
type ProbeResult struct {
	Outcome string // "ok", "lineFailed" or "engineUnavailable"
	RTT     time.Duration
}

// Fault is a test-only fault in a 1.0 test build.
type Fault struct {
	// Kind "udp-destroy-notifications": the engine's listener on the
	// sock_diag multicast groups SKNLGRP_INET_UDP_DESTROY and
	// SKNLGRP_INET6_UDP_DESTROY (5.3) stops seeing its messages as Mode
	// says, for both families, until the engine stops. Only the 1 s
	// reconciliation dump can then catch a reused port.
	Kind string
	// Mode "drop" loses every notification; "delay" delivers each after Delay.
	Mode  string
	Delay time.Duration
}

// FaultAck confirms a fault is in effect, in the engine's words.
type FaultAck struct {
	Active      bool
	Description string
}

// Histogram is a latency histogram: Counts[i] observations at or under
// BoundsMicros[i], and Counts[len(BoundsMicros)] above the last bound.
type Histogram struct {
	BoundsMicros []int64
	Counts       []int64
}

// Total is the number of observations.
func (h Histogram) Total() int64 {
	var n int64
	for _, c := range h.Counts {
		n += c
	}
	return n
}

// Sub is the histogram of observations made since prev (same bounds).
func (h Histogram) Sub(prev Histogram) (Histogram, error) {
	if len(prev.Counts) == 0 {
		return h, nil
	}
	if len(prev.Counts) != len(h.Counts) || len(prev.BoundsMicros) != len(h.BoundsMicros) {
		return Histogram{}, errors.New("histograms with different buckets")
	}
	out := Histogram{BoundsMicros: h.BoundsMicros, Counts: make([]int64, len(h.Counts))}
	for i := range h.Counts {
		if out.Counts[i] = h.Counts[i] - prev.Counts[i]; out.Counts[i] < 0 {
			return Histogram{}, errors.New("a histogram count went down")
		}
	}
	return out, nil
}

// Quantile is the upper bound of the bucket holding quantile q; ok is false
// when it lies above the last bound or there are no observations.
func (h Histogram) Quantile(q float64) (time.Duration, bool) {
	total := h.Total()
	if total == 0 {
		return 0, false
	}
	want := int64(float64(total)*q + 0.999999)
	var seen int64
	for i, c := range h.Counts {
		seen += c
		if seen >= want {
			if i >= len(h.BoundsMicros) {
				return 0, false
			}
			return time.Duration(h.BoundsMicros[i]) * time.Microsecond, true
		}
	}
	return 0, false
}

// Stats are the engine counters the suite reads (5.6, 5.10).
type Stats struct {
	// LookupLatency is every owner lookup since the engine started.
	LookupLatency   Histogram
	LookupMisses    int64
	LookupAmbiguous int64
	// Admitted is the combining counter k: new flows and UDP sessions
	// admitted (5.4).
	Admitted int64
	// Raw keeps every counter the engine sent.
	Raw map[string]float64
}

// Controller is one attached control session (2, 5.10). The engine hands out
// its epoch (5.9), and every command carries {instance id, epoch}: a command
// from a fenced session, or for another instance, is refused.
type Controller interface {
	InstanceID() string
	Epoch() uint64
	// Renew renews the lease once.
	Renew(ctx context.Context) error
	// SetAutoRenew turns the session's background renewal (every 5 s) on or
	// off; off lets the 30 s lease lapse.
	SetAutoRenew(on bool)
	Start(ctx context.Context, rev Revision, cfg Config) (Ack, error)
	Apply(ctx context.Context, rev Revision, cfg Config) (Ack, error)
	Stop(ctx context.Context) error
	Flows(ctx context.Context, cursor string) (FlowPage, error)
	Totals(ctx context.Context) (Totals, error)
	// CloseFlows is closeFlows{opId, selector, startedBefore}; startedBefore
	// 0 means no cutoff.
	CloseFlows(ctx context.Context, opID string, sel Selector, startedBefore uint64) (CloseResult, error)
	// Probe is probe{opId, line, operator}; kind is "quick" (TCP) or "full".
	Probe(ctx context.Context, opID string, line LineID, operator, kind string) (ProbeResult, error)
	Predict(ctx context.Context, app App) (map[LineID]float64, error)
	Stats(ctx context.Context) (Stats, error)
	InjectFault(ctx context.Context, f Fault) (FaultAck, error)
}

// V1 is 1.0's engine: a Driver whose control session and protocol are open
// to the suite. Driver.Start attaches the first session and starts revision 1.
type V1 interface {
	Driver
	// Hello greets the engine on a fresh connection.
	Hello(ctx context.Context) (Hello, error)
	// Attach opens a new control session, fencing out the current one.
	Attach(ctx context.Context) (Controller, error)
	// Session is the session the Driver methods use.
	Session() Controller
	// WaitExit waits for the engine process to exit.
	WaitExit(ctx context.Context) error
}
