package lifecycle

import (
	"context"
	"github.com/AyoubAchour/net-switch/internal/faultpoint"
	"github.com/AyoubAchour/net-switch/internal/service"
	"time"
)

func sessionPresence(data string) func(string, uint32) (bool, error) {
	return func(owner string, ignored uint32) (bool, error) {
		if present, known := faultpoint.OwnerSession(data, owner); known {
			return present, nil
		}
		return ownerSessionPresent(owner, ignored)
	}
}

func runSessionEvents(ctx context.Context, events <-chan service.Event, owner string, remote *Remote, power func(bool), stop func() error, log func(string), query func(string, uint32) (bool, error)) {
	// State polling also covers delayed WTS updates and missed logind signals.
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	present, initialErr := query(owner, ^uint32(0))
	known := initialErr == nil
	var recheckUntil time.Time
	suspended := false
	check := func(force bool) {
		next, err := query(owner, ^uint32(0))
		if err != nil {
			log("owner session query unavailable; retaining routing state: " + err.Error())
			return
		}
		if !next && (!known || present || force || time.Now().Before(recheckUntil)) {
			if err := stop(); err != nil {
				log("owner sign-out stop failed; retrying: " + err.Error())
				return
			}
			recheckUntil = time.Time{}
		}
		present, known = next, true
	}
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-events:
			if event.Suspend {
				suspended = true
				power(true)
			}
			if event.Resume || event.Logoff || event.SessionChanged {
				recheckUntil = time.Now().Add(10 * time.Second)
			}
			if event.Resume {
				// Check owner state before allowing a new start after wake.
				// Resume can arrive even when this process missed suspend.
				if !suspended {
					power(true)
				}
				remote.Wake()
				check(true)
				suspended = false
				power(false)
			}
		case <-tick.C:
			check(false)
		}
	}
}
