package lifecycle

import (
	"context"
	"errors"
	"github.com/AyoubAchour/net-switch/internal/service"
	"testing"
)

func TestEnrollmentDuringStartupAndPartialRetry(t *testing.T) {
	step, restarts, aclCalls := 0, 0, 0
	ops := ownerServices{
		setOwner: func(string) error {
			aclCalls++
			if aclCalls == 1 {
				return errors.New("injected ACL failure")
			}
			return nil
		},
		query: func() (service.Status, error) {
			switch step {
			case 0:
				return service.Status{PID: 1}, nil
			case 1:
				return service.Status{PID: 1, Running: true}, nil
			case 2:
				return service.Status{Stopped: true}, nil
			default:
				return service.Status{PID: 2, Running: true}, nil
			}
		},
		activeOwner: func(context.Context) (string, error) {
			if step < 3 {
				return "previous", nil
			}
			return "new", nil
		},
		restart: func(context.Context) error { restarts++; return nil },
		pause: func(context.Context) error {
			step++
			if step > 4 {
				return errors.New("did not settle")
			}
			return nil
		},
	}
	if err := settleOwner(context.Background(), "new", ops); err == nil {
		t.Fatal("injected ACL error hidden")
	}
	// owner.json already contains new at this point; retry still reconciles
	// the ACL and the old-owner process that is finishing startup.
	if err := settleOwner(context.Background(), "new", ops); err != nil {
		t.Fatal(err)
	}
	if restarts != 1 || aclCalls != 2 || step != 3 {
		t.Fatal("owner transition incomplete", step, restarts, aclCalls)
	}
	restarts = 0
	if err := settleOwner(context.Background(), "new", ops); err != nil || restarts != 0 {
		t.Fatal("same live owner restarted", err)
	}
}
