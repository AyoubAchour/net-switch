package lifecycle

import (
	"context"
	"github.com/AyoubAchour/net-switch/internal/faultpoint"
	"github.com/AyoubAchour/net-switch/internal/service"
	"time"
)

// A hybrid shutdown signs out every owner session while retaining the kernel
// boot identity. Persisting wanted=false on that OS event prevents boot-time
// recovery from starting routing before the next authenticated sign-in.
func handleSessionEvent(event service.Event, owner string, present func(string, uint32) (bool, error), stop func() error, log func(string)) {
	if !event.Resume && !event.Logoff && !event.SessionChanged {
		return
	}
	signedIn, err := present(owner, ^uint32(0))
	if err != nil {
		log("cannot verify owner session after power/session change: " + err.Error())
		return
	}
	if !signedIn {
		if err := stop(); err != nil {
			log("stop routing until owner signs in: " + err.Error())
		}
	}
}

func sessionPresence(data string) func(string, uint32) (bool, error) {
	return func(owner string, ignored uint32) (bool, error) {
		if present, known := faultpoint.OwnerSession(data, owner); known {
			return present, nil
		}
		return ownerSessionPresent(owner, ignored)
	}
}

func runSessionEvents(ctx context.Context, events <-chan service.Event, owner string, remote *Remote, stop func() error, log func(string), query func(string, uint32) (bool, error)) {
	// State polling also covers delayed WTS updates and missed logind signals.
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	present, initialErr := query(owner, ^uint32(0))
	known := initialErr == nil
	var recheckUntil time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-events:
			if event.Resume {
				remote.Wake()
			}
			if event.Resume || event.Logoff || event.SessionChanged {
				recheckUntil = time.Now().Add(10 * time.Second)
			}
		case <-tick.C:
			next, err := query(owner, ^uint32(0))
			if err != nil {
				log("owner session query unavailable; retaining routing state: " + err.Error())
				continue
			}
			if !next && (!known || present || time.Now().Before(recheckUntil)) {
				if err := stop(); err != nil {
					log("owner sign-out stop failed; retrying: " + err.Error())
					continue
				}
				recheckUntil = time.Time{}
			}
			present = next
			known = true
		}
	}
}
