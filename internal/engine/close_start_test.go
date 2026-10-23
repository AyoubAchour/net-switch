package engine

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
)

type stagedCloseTun struct {
	*testfake.Tun
	once           sync.Once
	begun, release chan struct{}
	err            error
	joined         atomic.Bool
}

func (t *stagedCloseTun) BeginClose() {
	t.once.Do(func() {
		t.Tun.Close() // unblock real engine packet pumps
		close(t.begun)
	})
}
func (t *stagedCloseTun) Close() error {
	t.BeginClose()
	<-t.release
	t.joined.Store(true)
	return t.err
}

type stagedCloseRoutes struct {
	testfake.Routes
	tun        *stagedCloseTun
	cleanup    chan struct{}
	quiesced   bool
	cleanupErr error
}

func (r *stagedCloseRoutes) Quiesce() { r.quiesced = true }
func (r *stagedCloseRoutes) Cleanup(context.Context) error {
	select {
	case <-r.tun.begun:
	default:
		return errors.New("cleanup preceded native close")
	}
	if !r.tun.joined.Load() {
		return errors.New("journal mutation overlapped session retirement")
	}
	if !r.quiesced {
		return errors.New("route monitor was not joined before cleanup")
	}
	close(r.cleanup)
	return r.cleanupErr
}

func TestStopJoinsNativeCloseBeforeCleanupEvenAfterFailure(t *testing.T) {
	for _, cleanupFails := range []bool{false, true} {
		tunErr := errors.New("native close result")
		tun := &stagedCloseTun{Tun: testfake.NewTun(), begun: make(chan struct{}), release: make(chan struct{}), err: tunErr}
		routes := &stagedCloseRoutes{tun: tun, cleanup: make(chan struct{})}
		if cleanupFails {
			routes.cleanupErr = errors.New("cleanup failed")
		}
		e := New(context.Background(), Dependencies{OpenTun: func(context.Context) (platform.TunDevice, error) { return tun, nil },
			Routes: routes, Dialer: testfake.Dialer{}, Owners: &testfake.Owners{}}, flows.Defaults(), nil)
		config := policy.Config{Lines: []platform.Line{{ID: "A"}}}
		if _, err := e.Start(context.Background(), policy.Revision{N: 1, Hash: policy.Hash(config), Config: config}); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		fatal := make(chan error, 1)
		e.OnFatal = func(err error) { fatal <- err }
		go func() { done <- e.Stop(context.Background()) }()
		select {
		case <-tun.begun:
		case <-time.After(time.Second):
			close(tun.release)
			t.Fatal("native teardown did not begin")
		}
		select {
		case <-routes.cleanup:
			close(tun.release)
			t.Fatal("journal mutation began before session joined")
		default:
		}
		select {
		case err := <-done:
			t.Fatalf("stop returned before native teardown completed: %v", err)
		default:
		}
		close(tun.release)
		select {
		case err := <-done:
			if !errors.Is(err, tunErr) || (cleanupFails && !errors.Is(err, routes.cleanupErr)) {
				t.Fatalf("stop lost a close/cleanup error: %v", err)
			}
			select {
			case <-routes.cleanup:
			default:
				t.Fatal("cleanup was not attempted after joining")
			}
			select {
			case failure := <-fatal:
				if !errors.Is(failure, tunErr) {
					t.Fatal(failure)
				}
			default:
				t.Fatal("retirement failure did not force service exit")
			}
		case <-time.After(time.Second):
			t.Fatal("stop did not join native completion")
		}
	}
}

func TestStartRollbackRetirementFailureIsFatal(t *testing.T) {
	release := make(chan struct{})
	close(release)
	tunErr := errors.New("retirement failed during rollback")
	tun := &stagedCloseTun{Tun: testfake.NewTun(), begun: make(chan struct{}), release: release, err: tunErr}
	routes := &stagedCloseRoutes{tun: tun, cleanup: make(chan struct{})}
	routes.Fail = "prepare"
	e := New(context.Background(), Dependencies{OpenTun: func(context.Context) (platform.TunDevice, error) { return tun, nil }, Routes: routes, Dialer: testfake.Dialer{}, Owners: &testfake.Owners{}}, flows.Defaults(), nil)
	fatal := make(chan error, 1)
	e.OnFatal = func(err error) { fatal <- err }
	config := policy.Config{Lines: []platform.Line{{ID: "A"}}}
	_, err := e.Start(context.Background(), policy.Revision{N: 1, Hash: policy.Hash(config), Config: config})
	if !errors.Is(err, tunErr) {
		t.Fatal("rollback lost retirement failure", err)
	}
	select {
	case failure := <-fatal:
		if !errors.Is(failure, tunErr) {
			t.Fatal(failure)
		}
	default:
		t.Fatal("rollback left failed retirement idle")
	}
	select {
	case <-routes.cleanup:
	default:
		t.Fatal("rollback never attempted journal cleanup")
	}
}
