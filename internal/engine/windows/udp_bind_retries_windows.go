//go:build windows

package winengine

import (
	"errors"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/winclock"
	"golang.org/x/sys/windows"
)

// Windows' automatic port choice sometimes refuses while dynamic ports are
// free (SYSTEM-DESIGN 5.9): a UDP bind to port 0 with WSAENOBUFS, and a TCP
// dial either at its bind to port 0 or, when the choice is deferred to the
// connect (SO_REUSE_UNICASTPORT), at ConnectEx with WSAEADDRINUSE. After such
// a refusal the engine makes a few fresh attempts, each with a new socket,
// and Windows still chooses the port. TCP dials get the same treatment as the
// UDP bind (2026-10-22, a design decision recorded in the spec). The counters
// say whether the attempts help; every final refusal is kept with its flow.
const (
	freshAttempts = 4
	freshWindow   = 10 * time.Millisecond
)

// portRetries counts one protocol's refusals and fresh attempts. The zero
// value is ready.
type portRetries struct {
	firstRefusals atomic.Uint64
	freshAttempts atomic.Uint64
	// recoveredOn[i] counts opens that succeeded on fresh attempt i+1.
	recoveredOn [freshAttempts]atomic.Uint64
	// finalFailures counts opens that ended refused by the port choice after
	// their fresh attempts: the hard gate's input, one per final refusal
	// recorded. otherFailures counts opens whose fresh attempt got a port and
	// then failed otherwise (refused by the peer, timed out, cancelled).
	finalFailures atomic.Uint64
	otherFailures atomic.Uint64
	// windowEnded counts refusals whose fresh attempts stopped at the time
	// window before reaching freshAttempts.
	windowEnded atomic.Uint64
	// now reads the window's clock; nil is winclock.Now. Go's own clock on
	// Windows moves by timer ticks (up to 15.6 ms), coarser than the window.
	now func() time.Duration
}

// retryOutcome is how one open ended: how many attempts it made, and
// whether it ended refused by the automatic port choice (a final refusal).
type retryOutcome struct {
	Attempts int
	Refused  bool
}

// udpPortRefusal is the UDP bind's refusal, as measured (WSAENOBUFS). A TCP
// dial retries either port-choice refusal, at its bind or its connect
// (portLimit: WSAENOBUFS or WSAEADDRINUSE).
func udpPortRefusal(err error) bool { return errors.Is(err, windows.WSAENOBUFS) }

// retryOpen runs one open: the first attempt, then, only after a refusal of
// the automatic port choice (retryable), up to freshAttempts fresh ones; none
// starts once freshWindow has passed since the first refusal, on the precise
// clock. Any other error ends the open at once. The outcome is a final
// refusal exactly when the last error is retryable, the same test the
// callers' records use, so the gated count and the records agree.
func retryOpen[T any](r *portRetries, retryable func(error) bool, attempt func() (T, error)) (T, retryOutcome, error) {
	result, err := attempt()
	outcome := retryOutcome{Attempts: 1}
	if err == nil || !retryable(err) {
		return result, outcome, err
	}
	now := r.now
	if now == nil {
		now = winclock.Now
	}
	r.firstRefusals.Add(1)
	refused := now()
	for n := range freshAttempts {
		if now()-refused >= freshWindow {
			r.windowEnded.Add(1)
			break
		}
		r.freshAttempts.Add(1)
		outcome.Attempts++
		if result, err = attempt(); err == nil {
			r.recoveredOn[n].Add(1)
			return result, outcome, nil
		}
		if !retryable(err) {
			break
		}
	}
	if retryable(err) {
		outcome.Refused = true
		r.finalFailures.Add(1)
	} else {
		r.otherFailures.Add(1)
	}
	return result, outcome, err
}

func (r *portRetries) stats() map[string]any {
	recovered := make([]uint64, freshAttempts)
	for i := range recovered {
		recovered[i] = r.recoveredOn[i].Load()
	}
	return map[string]any{"firstRefusals": r.firstRefusals.Load(), "freshAttempts": r.freshAttempts.Load(),
		"recoveredOnFreshAttempt": recovered, "finalFailures": r.finalFailures.Load(), "otherFailures": r.otherFailures.Load(),
		"windowEnded": r.windowEnded.Load(), "maxFreshAttempts": freshAttempts, "windowMS": freshWindow.Milliseconds()}
}

// finalRefusal is one open that ended refused by the port choice after its
// fresh attempts, with the flow it was for. Kind is "flow" for a relay socket
// and "probe" for a line health probe, which has no app.
type finalRefusal struct {
	At          time.Time `json:"at"`
	Protocol    string    `json:"protocol"`
	Kind        string    `json:"kind"`
	Call        string    `json:"call"`
	Errno       uint32    `json:"errno"`
	Attempts    int       `json:"attempts"`
	Line        string    `json:"line"`
	Local       string    `json:"local"`
	Source      string    `json:"source,omitempty"`
	Destination string    `json:"destination,omitempty"`
	App         string    `json:"app,omitempty"`
	AppID       string    `json:"appId,omitempty"`
	PID         uint32    `json:"pid,omitempty"`
	Error       string    `json:"error"`
}

// finalRefusals keeps the last 16, a fixed bound for the stats reply: an
// owner path is at most 1,024 bytes and its ID 512 (flows.MaxOwnerBytes).
type finalRefusals struct {
	mu     sync.Mutex
	recent [16]finalRefusal
	count  uint64
}

func (f *finalRefusals) record(protocol, kind, line string, local netip.AddrPort, flow platform.FlowIdentity, attempts int, err error) {
	r := finalRefusal{At: time.Now(), Protocol: protocol, Kind: kind, Attempts: attempts, Line: line, Local: local.String(),
		App: engine.Clip(flow.Owner.Path, 1024), AppID: engine.Clip(flow.Owner.AppID, 512), PID: flow.Owner.PID, Error: engine.Clip(err.Error(), 512)}
	if flow.Source.IsValid() {
		r.Source = flow.Source.String()
	}
	if flow.Destination.IsValid() {
		r.Destination = flow.Destination.String()
	}
	var call *os.SyscallError
	if errors.As(err, &call) {
		r.Call = call.Syscall
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		r.Errno = uint32(errno)
	}
	f.mu.Lock()
	f.recent[f.count%uint64(len(f.recent))] = r
	f.count++
	f.mu.Unlock()
}

func (f *finalRefusals) stats() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	recent := make([]finalRefusal, 0, min(f.count, uint64(len(f.recent))))
	for i := f.count - uint64(cap(recent)); i < f.count; i++ {
		recent = append(recent, f.recent[i%uint64(len(f.recent))])
	}
	return map[string]any{"count": f.count, "recent": recent}
}
