package protocol

import (
	"os"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/policy"
)

// AwakeNow is the same clock used by the child lease and host failure window.
func AwakeNow() time.Time { return leaseNow() }

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

// Supervision is accessible only to the hosting bootstrap, never as a public
// protocol method. The host does not infer health from this status response.
func (s *Server) Supervision() (string, int, uint16, int64, uint64) {
	status := s.status()
	s.mu.Lock()
	epoch := s.epoch
	s.mu.Unlock()
	if r, ok := s.runtime.(interface{ ForwardingCheck() (int, uint16) }); ok {
		index, port := r.ForwardingCheck()
		if status.State == "on" && status.Applied == nil {
			index, port = 0, 0
		}
		return status.State, index, port, status.Started.UnixNano(), epoch
	}
	return status.State, 0, 0, status.Started.UnixNano(), epoch
}
