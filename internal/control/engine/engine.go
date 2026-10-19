// Package engine is the control service's engine boundary. Milestone two can
// implement it over IPC without giving the controller access to engine internals.
package engine

import (
	"context"
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
}

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
}
type CloseRequest struct {
	OperationID   string    `json:"opId"`
	Line          string    `json:"line"`
	Instance      string    `json:"engineInstanceId"`
	StartedBefore time.Time `json:"startedBefore"`
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
}
type ProbeResult struct {
	Outcome Outcome  `json:"outcome"`
	Delay   *float64 `json:"delay"`
}
type Connection struct {
	apps.Connection
	Host string
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
