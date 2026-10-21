package lifecycle

import (
	"context"
	"fmt"
	"time"

	"github.com/AyoubAchour/net-switch/internal/faultpoint"
	"github.com/AyoubAchour/net-switch/internal/service"
)

func sessionPresence(data string) func(string, uint32) (bool, error) {
	return func(owner string, ignored uint32) (bool, error) {
		if present, known := faultpoint.OwnerSession(data, owner); known {
			return present, nil
		}
		return ownerSessionPresent(owner, ignored)
	}
}

// maxPowerPause bounds a suspend whose resume never arrives. Windows sends
// suspend seconds before sleeping and nothing runs while asleep; Go's clock
// there counts sleep, so after a real sleep a lost resume is noticed on the
// first tick. Two minutes of a running process without a resume means the
// resume was lost, and keeping new starts paused would strand routing.
const maxPowerPause = 2 * time.Minute

// powerPause is a service's suspended state, bounded by maxPowerPause.
type powerPause struct {
	on    bool
	since time.Time
}

func (p *powerPause) set(suspend bool, now time.Time) { p.on, p.since = suspend, now }

// expired ends a pause that has lasted maxPowerPause and reports that it did.
func (p *powerPause) expired(now time.Time) bool {
	if !p.on || now.Sub(p.since) < maxPowerPause {
		return false
	}
	p.on = false
	return true
}

// The session query runs every second; an outage logs its first failure,
// then a summary at most this often, and a line when it recovers.
const sessionLogInterval = time.Minute

func runSessionEvents(ctx context.Context, events *service.EventQueue, owner string, remote *Remote, power func(bool), stop func() error, log func(string), query func(string, uint32) (bool, error)) {
	runSessionEventsWithClock(ctx, events, owner, remote, power, stop, log, query, time.Now, time.Second)
}

func runSessionEventsWithClock(ctx context.Context, events *service.EventQueue, owner string, remote *Remote, power func(bool), stop func() error, log func(string), query func(string, uint32) (bool, error), now func() time.Time, interval time.Duration) {
	// State polling also covers delayed WTS updates and missed logind signals.
	tick := time.NewTicker(interval)
	defer tick.Stop()
	present, initialErr := query(owner, ^uint32(0))
	known := initialErr == nil
	var recheckUntil, failureLogged time.Time
	var pause powerPause
	failures, unlogged := 0, 0
	check := func(force bool) {
		next, err := query(owner, ^uint32(0))
		if err != nil {
			failures++
			if failures == 1 || now().Sub(failureLogged) >= sessionLogInterval {
				log(fmt.Sprintf("owner session query unavailable; retaining routing state: %v (failures not logged since the previous report: %d)", err, unlogged))
				failureLogged, unlogged = now(), 0
			} else {
				unlogged++
			}
			return
		}
		if failures != 0 {
			log(fmt.Sprintf("owner session query available again after %d failed attempts", failures))
			failures, unlogged = 0, 0
		}
		if !next && (!known || present || force || now().Before(recheckUntil)) {
			if err := stop(); err != nil {
				log("owner sign-out stop failed; retrying: " + err.Error())
				return
			}
			recheckUntil = time.Time{}
		}
		present, known = next, true
	}
	resume := func(wasPaused bool) {
		// Check owner state before allowing a new start after wake.
		// Resume can arrive even when this process missed suspend.
		if !wasPaused {
			power(true)
		}
		remote.Wake()
		check(true)
		pause.set(false, now())
		power(false)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-events.Ready():
			for _, event := range events.Take() {
				if event.Suspend {
					pause.set(true, now())
					power(true)
				}
				if event.Resume || event.Logoff || event.SessionChanged {
					recheckUntil = now().Add(10 * time.Second)
				}
				if event.Resume {
					resume(pause.on)
				}
			}
		case <-tick.C:
			if pause.expired(now()) {
				log("no resume notification within two minutes of suspend; treating the system as awake")
				recheckUntil = now().Add(10 * time.Second)
				resume(true)
				continue
			}
			check(false)
		}
	}
}
