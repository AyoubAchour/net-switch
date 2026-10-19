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
// apps and servers see, plus what the engine reports about its flows.
package engine

import (
	"context"
	"errors"
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
	Protocol    string // "tcp", "udp" or "icmp"
	Source      netip.AddrPort
	Destination netip.AddrPort
	Lane        LineID // the lane (selector) it was decided by
	Line        LineID // the physical line carrying it
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

// Driver controls one engine under test.
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
	// Flows lists the open flows.
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

// V1 is the part of 1.0's control protocol with no baseline equivalent.
// Cases labelled requires-1.0 use it; the baseline driver doesn't implement it.
type V1 interface {
	Driver
	// Revision is the policy revision the engine has loaded (3.3).
	Revision(ctx context.Context) (n int64, hash string, err error)
	// CloseFlowsBefore is closeFlows with an operation id and a startedBefore
	// cutoff: only flows admitted before revision n was applied (3.3, 4.6).
	CloseFlowsBefore(ctx context.Context, opID string, sel Selector, startedBefore int64) (CloseResult, error)
	// Predict is predict{app}: the line, or for a shared app the distribution
	// of lines, a new flow would get. It doesn't advance the combining counter.
	Predict(ctx context.Context, app App) (map[LineID]float64, error)
	// Stats is stats: counters including lookup latency and misses (5.6).
	Stats(ctx context.Context) (Stats, error)
	// InjectFault turns on a test-only fault, for example "udp-destroy-drop"
	// (lose sock_diag destroy notifications, 5.3). Builds without test hooks
	// return ErrNotImplemented.
	InjectFault(ctx context.Context, fault string) error
}

// Stats are the engine counters the suite reads.
type Stats struct {
	LookupP95       time.Duration
	LookupMisses    int64
	LookupAmbiguous int64
	// Admitted is the combining counter k: new flows and UDP sessions
	// admitted (5.4).
	Admitted int64
	// Raw keeps every counter the engine sent.
	Raw map[string]float64
}
