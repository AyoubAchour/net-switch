// Package engine is the acceptance suite's view of a routing engine: the
// operations Net Switch's control service needs (SYSTEM-DESIGN.md section
// 5.10), without saying how an engine does them. Each engine under test has a
// driver:
//
//   - singbox: the baseline, sing-box as today's app configures it, plus the
//     Linux changes the feasibility spike found (LINUX-PLAN.md section 0).
//   - nsengine: netswitch-engine, 1.0's own engine. It speaks
//     internal/engine/protocol; the driver is a stub until the engine binary
//     serves that protocol on a control socket.
//
// The suite plays the control service: it picks lines, pins apps, points
// lanes and closes flows through a Driver, and judges the engine only by what
// apps and servers see, plus what the engine reports about its flows. V1 and
// Controller expose the parts of the protocol only 1.0 has, with every
// acknowledgement and refusal visible, so requires-1.0 cases can check them.
package engine

import (
	"context"
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
// network namespace. A driver finds what its engine needs from the interface
// (1.0's revisions carry each line's addresses).
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
	Revision    uint64 // the policy revision it was admitted under (1.0)
	Epoch       uint64 // the control epoch it was admitted in (1.0)
	Point       uint64 // the admission's place in the apply order (1.0)
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

// --- 1.0's control protocol (5.10), as internal/engine/protocol speaks it ---

// Revision is a policy revision: Control's number n and the hash of the
// revision's config as the engine checks it. The engine refuses a revision
// whose hash doesn't match its config, so only a driver can compute it; cases
// send n and a Config and read the hash back from the acknowledgement.
type Revision struct {
	N    uint64
	Hash string
}

// Applied is a revision in effect in this engine instance. Point is its
// apply point: closeFlows' startedBefore takes it, and flows admitted before
// it have a smaller Point.
type Applied struct {
	Revision
	Point uint64
}

// RefusalCode classifies a refusal the protocol defines, as opposed to a
// failure. Cases test codes, never message text.
type RefusalCode string

const (
	// RefusedFenced: the command isn't from the attached controller: another
	// engine instance, an older epoch, or no attach at all.
	RefusedFenced RefusalCode = "fenced"
	// RefusedLapsed: the lease expired or the engine is stopping.
	RefusedLapsed RefusalCode = "lapsed"
	// RefusedAttach: attach was refused (another instance, an epoch that
	// Control tried to pick, or cleanup under way).
	RefusedAttach RefusalCode = "attach-refused"
	// RefusedStale: a lower n than the revision in effect.
	RefusedStale RefusalCode = "stale-revision"
	// RefusedConflict: the same n with another hash.
	RefusedConflict RefusalCode = "revision-conflict"
	// RefusedInvalidRevision: n 0, or a hash that isn't the config's.
	RefusedInvalidRevision RefusalCode = "invalid-revision"
	// RefusedOperationConflict: an operation id reused with other arguments.
	RefusedOperationConflict RefusalCode = "operation-conflict"
	// RefusedSelector: not exactly one closure condition (an empty selector
	// included), or one Control handles itself.
	RefusedSelector RefusalCode = "invalid-selector"
	// RefusedCapacity: a budget of section 5.9 is exhausted.
	RefusedCapacity RefusalCode = "capacity"
	// RefusedNotRunning: routing isn't running.
	RefusedNotRunning RefusalCode = "not-running"
)

// Refusal is a refusal the protocol defines, as opposed to a failure.
type Refusal struct {
	Code    RefusalCode
	Message string // the engine's own words
}

func (r *Refusal) Error() string { return fmt.Sprintf("refused (%s): %s", r.Code, r.Message) }

// RefusedWith reports whether err is a refusal with that code.
func RefusedWith(err error, code RefusalCode) bool {
	var r *Refusal
	return errors.As(err, &r) && r.Code == code
}

// Hello is the engine's greeting (5.10).
type Hello struct {
	Version      string
	InstanceID   string
	Capabilities []string
	// Epoch is the newest epoch the engine has handed out (0: none yet).
	Epoch uint64
	// Applied is the revision in effect in this instance: nil until start.
	Applied *Applied
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
	OK      bool
	Latency time.Duration
	Error   string
}

// Prediction is predict's answer: a pinned app's line (and whether it's
// blocked), or, for an unpinned app while combining, the share each line
// gets.
type Prediction struct {
	Line         LineID
	Distribution map[LineID]float64
	Blocked      bool
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

// Stats are the engine's counters and gauges (5.6, 5.9, 5.10).
type Stats struct {
	// Gauges: what's in use now. TimeWait counts retained TIME_WAIT
	// endpoints, which aren't live flows (5.9).
	Flows, Handshakes, UDP, Unknown, UnknownUDP, TimeWait int64
	// Byte budgets in use (5.9).
	TCPBytes, PendingBytes, SnapshotBytes int64
	// Counters since the engine started.
	Admitted        uint64 // the combining counter k: flows admitted (5.4)
	Rejected        uint64
	DroppedNotices  uint64 // rejection notices over the rate limit
	TimeWaitSkipped uint64 // closings that skipped TIME_WAIT at its cap
	EventsDropped   uint64
	// Owner lookups (5.6): how many, how many found no owner or several, and
	// the time they took in total.
	LookupCount, LookupMisses, LookupAmbiguous uint64
	LookupTime                                 time.Duration
	// Counters reports every other counter the engine sent, by name.
	Counters map[string]uint64
}

// LookupMean is the mean owner lookup time (0 without lookups).
func (s Stats) LookupMean() time.Duration {
	if s.LookupCount == 0 {
		return 0
	}
	return s.LookupTime / time.Duration(s.LookupCount)
}

// Controller is one attached control session (2, 5.10). The engine hands out
// its epoch at attach (5.9); Control never picks one. Every command carries
// {instance id, epoch}, and the engine refuses one from a fenced session.
type Controller interface {
	InstanceID() string
	Epoch() uint64
	// Renew renews the lease once.
	Renew(ctx context.Context) error
	// SetAutoRenew turns the session's background renewal (every 5 s) on or
	// off; off lets the 30 s lease lapse.
	SetAutoRenew(on bool)
	// Start and Apply send revision n of cfg; the driver computes the hash
	// the engine checks, and the acknowledgement carries it.
	Start(ctx context.Context, n uint64, cfg Config) (Applied, error)
	Apply(ctx context.Context, n uint64, cfg Config) (Applied, error)
	Stop(ctx context.Context) error
	Flows(ctx context.Context, cursor string) (FlowPage, error)
	Totals(ctx context.Context) (Totals, error)
	// CloseFlows is closeFlows{opId, selector, startedBefore}; startedBefore
	// 0 means no cutoff.
	CloseFlows(ctx context.Context, opID string, sel Selector, startedBefore uint64) (CloseResult, error)
	// Probe is probe{opId, line, operator} (4.5).
	Probe(ctx context.Context, opID string, line LineID, operator string) (ProbeResult, error)
	Predict(ctx context.Context, app App) (Prediction, error)
	Stats(ctx context.Context) (Stats, error)
	InjectFault(ctx context.Context, f Fault) (FaultAck, error)
}

// V1 is 1.0's engine: a Driver whose control session and protocol are open
// to the suite. Driver.Start attaches the first session and starts revision 1.
type V1 interface {
	Driver
	// Hello greets the engine on a fresh connection.
	Hello(ctx context.Context) (Hello, error)
	// Attach opens a new control session, fencing out the current one, and
	// makes it the session the Driver methods use from then on: the old
	// session stops renewing and the new one renews itself.
	Attach(ctx context.Context) (Controller, error)
	// Session is the session the Driver methods use.
	Session() Controller
	// WaitExit waits for the engine process to exit.
	WaitExit(ctx context.Context) error
}
