// Package flowapi is the shared boundary between packet forwarding and control.
package flowapi

import (
	"context"
	"net/netip"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

type Decision struct {
	Lane     string `json:"lane"`
	Line     string `json:"line"`
	Revision uint64 `json:"revision"`
}

// Begin reserves global capacity before lookup, goroutines or buffers. Resolve
// performs per-owner admission and the policy decision as one transaction.
type Controller interface {
	Begin(string, platform.Tuple) (Ticket, error)
	AllowReject(string) bool
	ReservePending(int) bool
	ReleasePending(int)
}

type Ticket interface {
	Resolve(platform.Owner) (Decision, error)
	Buffers() (receive, send int)
	Established(netip.Addr)
	Add(up, down uint64)
	SetCancel(context.CancelFunc)
	// TimeWait releases live-flow capacity and reserves a retained endpoint
	// (TIME_WAIT or payload-free LAST_ACK/CLOSING). Repeated calls are safe.
	// False skips TIME_WAIT. Closing reserves the same slot for a FIN-only
	// endpoint, or counts overflow while it waits for its final ACK. Overflow
	// must get a grace period before a reset. EndTimeWait releases either.
	TimeWait() bool
	Closing() bool
	EndTimeWait()
	// Retire releases live-flow capacity while preserving final accounting.
	Retire()
	Close()
}

type Output interface{ Send([]byte) bool }

const UDPReadBuffer = 9 << 10

type Event struct {
	Type    string `json:"event"`
	Message string `json:"message"`
	App     string `json:"app,omitempty"`
	Line    string `json:"line,omitempty"`
}
