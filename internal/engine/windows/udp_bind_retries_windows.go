//go:build windows

package winengine

import (
	"errors"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
)

// Windows' automatic port choice (bind to port 0) sometimes refuses with
// WSAENOBUFS while dynamic ports are free (SYSTEM-DESIGN 5.9). After such a
// refusal the engine makes a few fresh attempts, each with a new socket, and
// Windows still chooses the port. The counters say whether they help; if
// they never do, this code goes.
const (
	udpFreshAttempts = 4
	udpFreshWindow   = 10 * time.Millisecond
)

type udpBindRetries struct {
	firstRefusals atomic.Uint64
	freshAttempts atomic.Uint64
	// recoveredOn[i] counts opens that succeeded on fresh attempt i+1.
	recoveredOn   [udpFreshAttempts]atomic.Uint64
	finalFailures atomic.Uint64
	// windowEnded counts refusals whose fresh attempts stopped at the time
	// window before reaching udpFreshAttempts.
	windowEnded atomic.Uint64
}

// open runs one engine UDP open: the first attempt, then, only after a
// WSAENOBUFS refusal, up to udpFreshAttempts fresh ones within
// udpFreshWindow. Any other error ends the open at once.
func (r *udpBindRetries) open(attempt func() (*udpSocket, error)) (*udpSocket, error) {
	s, err := attempt()
	if err == nil || !errors.Is(err, windows.WSAENOBUFS) {
		return s, err
	}
	r.firstRefusals.Add(1)
	refused := time.Now()
	for n := range udpFreshAttempts {
		if time.Since(refused) >= udpFreshWindow {
			r.windowEnded.Add(1)
			break
		}
		r.freshAttempts.Add(1)
		if s, err = attempt(); err == nil {
			r.recoveredOn[n].Add(1)
			return s, nil
		}
		if !errors.Is(err, windows.WSAENOBUFS) {
			break
		}
	}
	r.finalFailures.Add(1)
	return nil, err
}

func (r *udpBindRetries) stats() map[string]any {
	recovered := make([]uint64, udpFreshAttempts)
	for i := range recovered {
		recovered[i] = r.recoveredOn[i].Load()
	}
	return map[string]any{"firstRefusals": r.firstRefusals.Load(), "freshAttempts": r.freshAttempts.Load(),
		"recoveredOnFreshAttempt": recovered, "finalFailures": r.finalFailures.Load(),
		"windowEnded": r.windowEnded.Load(), "maxFreshAttempts": udpFreshAttempts, "windowMS": udpFreshWindow.Milliseconds()}
}
