package engine

import (
	"context"
	"errors"
	"sync"
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
		return errors.New("cleanup did not overlap native close")
	}
	if !r.quiesced {
		return errors.New("route monitor was not joined before cleanup")
	}
	close(r.cleanup)
	return r.cleanupErr
}

func TestStopOverlapsNativeCloseButJoinsEvenAfterCleanupFailure(t *testing.T) {
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
		go func() { done <- e.Stop(context.Background()) }()
		select {
		case <-routes.cleanup:
		case <-time.After(time.Second):
			close(tun.release)
			t.Fatal("route cleanup waited for unrelated native teardown")
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
		case <-time.After(time.Second):
			t.Fatal("stop did not join native completion")
		}
	}
}
