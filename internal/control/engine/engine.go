// Package engine is the control service's engine boundary. The lifecycle
// package implements it over IPC without exposing engine process internals.
package engine

import (
	"context"
	"errors"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/lines"
)

type Policy struct {
	Lines    []lines.Line      `json:"lines"`
	AppLines apps.Pins         `json:"appLines"`
	Combine  bool              `json:"combine"`
	Shares   lines.Shares      `json:"shares"`
	Blocked  []string          `json:"blocked"`
	Lanes    map[string]string `json:"lanes"`
	IPv6     bool              `json:"ipv6"`
}

type Snapshot struct {
	Status          string
	Error           *string
	ProxyPort       *int
	StartedAt       time.Time
	StartedWith     *Policy
	Policy          Policy
	PID             int
	Instance        string
	AppliedRevision uint64
	AppliedHash     string
	AppliedAt       time.Time
	// AppliedPoint is the native engine's apply point for AppliedRevision. The
	// temporary adapter has no points and leaves it zero.
	AppliedPoint uint64 `json:"appliedPoint,omitempty"`
	FailureID    string `json:"failureId,omitempty"`
	// Reason classifies an error exit: "adapter-lost" is a clean exit 3 whose
	// cleanup completed (spec §5.1); it restarts without using the crash
	// budget until the fourth loss in ten minutes. Empty means ordinary failure.
	Reason string `json:"reason,omitempty"`
}

const ReasonAdapterLost = "adapter-lost"

type Revision struct {
	Number uint64 `json:"n"`
	Hash   string `json:"sha256"`
	Policy Policy `json:"policy"`
}
type Acknowledgement struct {
	Number    uint64    `json:"n"`
	Hash      string    `json:"sha256"`
	Instance  string    `json:"engineInstanceId"`
	AppliedAt time.Time `json:"appliedAt"`
	// Point is the native apply point; closure cutoffs are expressed in it.
	Point uint64 `json:"point,omitempty"`
}
type CloseRequest struct {
	OperationID   string    `json:"opId"`
	Line          string    `json:"line"`
	Instance      string    `json:"engineInstanceId"`
	StartedBefore time.Time `json:"startedBefore"`
	// StartedBeforePoint is the native cutoff: only flows admitted before this
	// apply point in this engine instance are closed (spec §3.3).
	StartedBeforePoint uint64 `json:"startedBeforePoint,omitempty"`
	// BeforeRevision names the apply point while its timestamp is not yet known.
	BeforeRevision uint64 `json:"startedBeforeRevision,omitempty"`
	// The temporary adapter also pins IDs because Clash has no revision-based
	// flow identity. The real engine can enforce the apply-point cutoff itself.
	ConnectionIDs []string `json:"connectionIds"`
}
type CloseResult struct{ Closed, Failed, Gone int }

type Outcome string

const (
	OK          Outcome = "ok"
	LineFailed  Outcome = "lineFailed"
	Unavailable Outcome = "engineUnavailable"
)

type ProbeRequest struct {
	OperationID string
	Line        string
	Index       uint32
	Target      string
	Quick       bool
	Custom      bool
}
type ProbeResult struct {
	Outcome Outcome  `json:"outcome"`
	Delay   *float64 `json:"delay"`
	// Kind is "quick" (TCP connect) or "full" (HTTPS). Control accepts a result
	// only when it matches the kind it asked for: a quick pass never restores
	// a line that needs a full check.
	Kind string `json:"kind,omitempty"`
	// Instance is the engine instance that answered. A result from an instance
	// that is no longer current is dropped.
	Instance string `json:"engineInstanceId,omitempty"`
}
type Connection struct {
	apps.Connection
	// Host is the destination name when the engine knows one, otherwise the
	// destination address of a flow whose upstream connection is established.
	// It is empty for flows still connecting, so they never count as evidence.
	Host string
}

// Counter is a cumulative byte count within one accounting generation. A new
// generation for the same identity starts at zero only after the old, idle one
// was acknowledged.
type Counter struct {
	Up, Down   uint64
	Generation string
}

// TotalsPage is one page of the engine's exact per-app and per-line accounting.
// Every page of one read shares the receipt; the first call freezes the counters.
type TotalsPage struct {
	Instance string
	Apps     map[string]Counter
	Lines    map[string]Counter
	Cursor   string
	Receipt  string
	Count    int
}

// ErrNoAccounting means this engine has no paged accounting (the temporary
// adapter). Control then keeps today's adapter-counter usage only.
var ErrNoAccounting = errors.New("engine has no paged accounting")

// Accounting is optional. Control durably commits every page's high-water marks
// before AckTotals, so a lost acknowledgement is retried with the same opId and
// an expired receipt is followed by a fresh, equally safe full read.
type Accounting interface {
	Totals(ctx context.Context, cursor string) (TotalsPage, error)
	AckTotals(ctx context.Context, opID, receipt string) error
}

// Apply acknowledges only after the adapter has applied all parts of a policy.
// Policy closures name their revision before Apply; acknowledgement resolves
// its cutoff. Explicit selections such as Reconnect retain their original time.
type Engine interface {
	Snapshot() Snapshot
	// Fail reports a control-side prerequisite failure without starting the engine.
	Fail(error)
	Start(context.Context, Policy) error
	Stop(context.Context) error
	Apply(context.Context, Revision) (Acknowledgement, error)
	CloseFlows(context.Context, CloseRequest) (CloseResult, error)
	Connections(context.Context) ([]Connection, error)
	Probe(context.Context, ProbeRequest) ProbeResult
}
