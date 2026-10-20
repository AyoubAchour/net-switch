package lifecycle

import (
	"context"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/internal/service"
	"time"
)

type ownerServices struct {
	setOwner    func(string) error
	query       func() (service.Status, error)
	activeOwner func(context.Context) (string, error)
	restart     func(context.Context) error
	pause       func(context.Context) error
}

func installedOwnerServices() ownerServices {
	return ownerServices{
		setOwner: service.SetOwner,
		query:    func() (service.Status, error) { return service.Query(service.Control) },
		activeOwner: func(ctx context.Context) (string, error) {
			rpc, err := ConnectStatus(ctx)
			if err != nil {
				return "", err
			}
			defer rpc.Close()
			var state struct {
				Owner Owner `json:"owner"`
			}
			err = rpc.Call(ctx, map[string]any{"method": "status"}, &state)
			return state.Owner.User, err
		},
		restart: func(ctx context.Context) error { return service.RequestRestart(ctx, service.Control) },
		pause:   func(ctx context.Context) error { return localipc.Pause(ctx, 100*time.Millisecond) },
	}
}

// Reconcile every phase even when owner.json already contains this user: a
// previous ctl invocation may have failed after the durable write. Startup is
// allowed to finish, then its actual owner is checked before reporting success.
func settleOwner(ctx context.Context, owner string, ops ownerServices) error {
	if err := ops.setOwner(owner); err != nil {
		return err
	}
	var restarting uint32
	for {
		status, err := ops.query()
		if err != nil {
			return err
		}
		if status.Stopped && restarting == 0 {
			return nil
		}
		if status.Running {
			active, err := ops.activeOwner(ctx)
			if err == nil && active == owner {
				return nil
			}
			if restarting != status.PID {
				if err := ops.restart(ctx); err != nil {
					return err
				}
				restarting = status.PID
			}
		}
		if err := ops.pause(ctx); err != nil {
			return err
		}
	}
}
