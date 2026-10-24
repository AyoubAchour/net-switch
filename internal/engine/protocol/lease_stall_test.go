package protocol

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
)

type stuckRuntime struct {
	runtimeFake
	entered chan struct{}
	release chan struct{}
}

func (r *stuckRuntime) Apply(ctx context.Context, v policy.Revision) (policy.Applied, error) {
	close(r.entered)
	<-r.release
	return r.runtimeFake.Apply(ctx, v)
}

// Spec §2: a lapsed lease stops forwarding. A command stuck inside the engine
// (a durable write that never returns) holds the mutation lock; the expiry
// must not wait on it forever but report the stall, so the host fails open.
// On main this call blocks until the command returns.
func TestExpiredLeaseDoesNotWaitOnAStuckCommand(t *testing.T) {
	old := leaseStallBound
	leaseStallBound = 100 * time.Millisecond
	t.Cleanup(func() { leaseStallBound = old })
	table := flows.New(flows.Defaults(), nil)
	runtime := &stuckRuntime{runtimeFake: runtimeFake{table: table}, entered: make(chan struct{}), release: make(chan struct{})}
	s := New(runtime, table, nil)
	if r := s.Handle(context.Background(), Request{ID: "attach", Method: "attach", Instance: s.Instance}); r.Error != "" {
		t.Fatal(r.Error)
	}
	start := revision(1)
	if r := s.Handle(context.Background(), Request{ID: "start", Method: "start", Instance: s.Instance, Epoch: 1, Revision: &start}); r.Error != "" {
		t.Fatal(r.Error)
	}
	stuck := revision(2)
	go s.Handle(context.Background(), Request{ID: "apply", Method: "apply", Instance: s.Instance, Epoch: 1, Revision: &stuck})
	<-runtime.entered
	s.mu.Lock()
	expired := s.expires.Add(time.Nanosecond)
	s.now = func() time.Time { return expired }
	s.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- s.CheckLease(context.Background()) }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrLeaseStalled) {
			t.Fatal("expiry with a stuck command must report the stall", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lease expiry waited on the stuck command")
	}
	if runtime.stops.Load() != 0 {
		t.Fatal("cleanup ran while the engine was still held")
	}
	// The stall is routed to its own hook, not to the cleanup-failure hook,
	// because a graceful cleanup would wait on the same lock.
	stalled := make(chan error, 1)
	s.OnLeaseStall = func(err error) { stalled <- err }
	s.OnCleanupFailure = func(err error) { t.Error("stall reported as a cleanup failure", err) }
	ctx, cancel := context.WithCancel(context.Background())
	go s.RunLease(ctx)
	select {
	case err := <-stalled:
		if !errors.Is(err, ErrLeaseStalled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunLease never reported the stall")
	}
	cancel()
	close(runtime.release)
	// Once the command returns, the ordinary lapse cleanup proceeds.
	if err := s.CheckLease(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runtime.stops.Load() != 1 {
		t.Fatal("cleanup did not run after the command released the engine")
	}
}
