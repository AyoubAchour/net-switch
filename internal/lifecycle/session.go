package lifecycle

import (
	"context"
	"github.com/AyoubAchour/net-switch/internal/service"
)

// A hybrid shutdown signs out every owner session while retaining the kernel
// boot identity. Persisting wanted=false on that OS event prevents boot-time
// recovery from starting routing before the next authenticated sign-in.
func handleSessionEvent(event service.Event, owner string, present func(string, uint32) (bool, error), stop func() error, log func(string)) {
	if !event.Resume && !event.Logoff {
		return
	}
	excluded := ^uint32(0)
	if event.Logoff {
		excluded = event.Session
	}
	signedIn, err := present(owner, excluded)
	if err != nil {
		log("cannot verify owner session after power/session change: " + err.Error())
	}
	if !signedIn {
		if err := stop(); err != nil {
			log("stop routing until owner signs in: " + err.Error())
		}
	}
}

func runSessionEvents(ctx context.Context, events <-chan service.Event, owner string, remote *Remote, stop func() error, log func(string)) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-events:
			if event.Resume {
				remote.Wake()
			}
			handleSessionEvent(event, owner, ownerSessionPresent, stop, log)
		}
	}
}
