package protocol

import (
	"os"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/policy"
)

// Status separates loaded forwarding from durable history and diagnostics.
// It never contains policy/flow arrays, so its wire size is fixed.
type Status struct {
	Instance  string          `json:"engineInstanceId"`
	PID       int             `json:"pid"`
	State     string          `json:"status"`
	Started   time.Time       `json:"startedAt"`
	Applied   *policy.Applied `json:"appliedRevision"`
	LastError string          `json:"lastError,omitempty"`
}

func (s *Server) status() Status {
	out := Status{Instance: s.Instance, PID: os.Getpid(), State: "off"}
	if runtime, ok := s.runtime.(interface{ LastError() string }); ok {
		out.LastError = runtime.LastError()
		if len(out.LastError) > 4096 {
			out.LastError = out.LastError[:4096]
		}
	}
	if runtime, ok := s.runtime.(interface{ LiveState() (string, time.Time) }); ok {
		out.State, out.Started = runtime.LiveState()
		if out.State == "on" {
			out.Applied = s.table.Applied()
		}
	} else if applied := s.table.Applied(); applied != nil {
		out.State, out.Applied = "on", applied
	}
	return out
}
