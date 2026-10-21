package protocol

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
)

type durableRuntime struct {
	runtimeFake
	initial, saved   uint64
	fail             bool
	entered, release chan struct{}
}

func (r *durableRuntime) InitialEpoch() uint64 { return r.initial }
func (r *durableRuntime) SaveEpoch(epoch uint64) error {
	if r.fail {
		return errors.New("epoch fsync failed")
	}
	r.saved = epoch
	return nil
}
func (r *durableRuntime) Start(ctx context.Context, rev policy.Revision) (policy.Applied, error) {
	if r.entered != nil {
		close(r.entered)
		<-r.release
	}
	return r.runtimeFake.Start(ctx, rev)
}
func TestEpochIsDurableBeforeAttachAck(t *testing.T) {
	table := flows.New(flows.Defaults(), nil)
	runtime := &durableRuntime{runtimeFake: runtimeFake{table: table}, initial: 17, fail: true}
	s := New(runtime, table, nil)
	request := Request{ID: "attach", Method: "attach", Instance: s.Instance}
	if r := s.Handle(context.Background(), request); r.Error == "" || s.epoch != 17 {
		t.Fatal("failed epoch commit was acknowledged", r)
	}
	runtime.fail = false
	r := call(t, s, request)
	if runtime.saved != 18 || r.Result.(map[string]any)["epoch"] != uint64(18) {
		t.Fatal("engine did not advance the durable counter", r)
	}
}
func TestSlowApplyAllowsRenewalButSerializesAttach(t *testing.T) {
	table := flows.New(flows.Defaults(), nil)
	runtime := &durableRuntime{runtimeFake: runtimeFake{table: table}, entered: make(chan struct{}), release: make(chan struct{})}
	s := New(runtime, table, nil)
	ctx := context.Background()
	call(t, s, Request{ID: "attach", Method: "attach", Instance: s.Instance})
	rev := revision(1)
	started := make(chan Reply, 1)
	go func() {
		started <- s.Handle(ctx, Request{ID: "start", Method: "start", Instance: s.Instance, Epoch: 1, Revision: &rev})
	}()
	<-runtime.entered
	renewed := make(chan Reply, 1)
	go func() {
		renewed <- s.Handle(ctx, Request{ID: "renew", Method: "renew", Instance: s.Instance, Epoch: 1})
	}()
	select {
	case reply := <-renewed:
		if reply.Error != "" {
			t.Fatal(reply.Error)
		}
	case <-time.After(time.Second):
		close(runtime.release)
		t.Fatal("slow apply blocked the control lease")
	}
	attached := make(chan Reply, 1)
	go func() { attached <- s.Handle(ctx, Request{ID: "reattach", Method: "attach", Instance: s.Instance}) }()
	select {
	case <-attached:
		close(runtime.release)
		t.Fatal("new controller overtook an accepted apply")
	case <-time.After(20 * time.Millisecond):
	}
	close(runtime.release)
	if reply := <-started; reply.Error != "" {
		t.Fatal(reply.Error)
	}
	if reply := <-attached; reply.Error != "" {
		t.Fatal(reply.Error)
	}
	if reply := s.Handle(ctx, Request{ID: "stale", Method: "renew", Instance: s.Instance, Epoch: 1}); reply.Error == "" {
		t.Fatal("old control remained active")
	}
}
func TestExpiryFencesBeforeWaitingForBlockedMutation(t *testing.T) {
	table := flows.New(flows.Defaults(), nil)
	runtime := &durableRuntime{runtimeFake: runtimeFake{table: table}, entered: make(chan struct{}), release: make(chan struct{})}
	s := New(runtime, table, nil)
	ctx := context.Background()
	call(t, s, Request{ID: "attach", Method: "attach", Instance: s.Instance})
	rev := revision(1)
	applied := make(chan Reply, 1)
	go func() {
		applied <- s.Handle(ctx, Request{ID: "start", Method: "start", Instance: s.Instance, Epoch: 1, Revision: &rev})
	}()
	<-runtime.entered
	s.mu.Lock()
	expired := s.expires.Add(time.Nanosecond)
	s.now = func() time.Time { return expired }
	s.mu.Unlock()
	if !s.Expired() {
		close(runtime.release)
		t.Fatal("blocked apply hid lease expiry")
	}
	if reply := s.Handle(ctx, Request{ID: "renew", Method: "renew", Instance: s.Instance, Epoch: 1}); reply.Error == "" {
		close(runtime.release)
		t.Fatal("expired controller renewed")
	}
	cleaned := make(chan error, 1)
	go func() { cleaned <- s.CheckLease(ctx) }()
	close(runtime.release)
	<-applied
	if err := <-cleaned; err != nil {
		t.Fatal(err)
	}
	if reply := s.Handle(ctx, Request{ID: "attach", Method: "attach", Instance: s.Instance}); reply.Error == "" {
		t.Fatal("attachment resurrected expired engine")
	}
}

func TestLeaseUsesInjectedClockForRenewalAndExpiry(t *testing.T) {
	table := flows.New(flows.Defaults(), nil)
	s := New(&runtimeFake{table: table}, table, nil)
	awake := time.Unix(100, 0)
	s.now = func() time.Time { return awake }
	call(t, s, Request{ID: "attach", Method: "attach", Instance: s.Instance})
	awake = awake.Add(20 * time.Second)
	if s.Expired() {
		t.Fatal("lease expired before the injected clock deadline")
	}
	call(t, s, Request{ID: "renew", Method: "renew", Instance: s.Instance, Epoch: 1})
	awake = awake.Add(Lease - time.Nanosecond)
	if s.Expired() {
		t.Fatal("lease expired before 30 awake seconds")
	}
	awake = awake.Add(time.Nanosecond)
	if !s.Expired() {
		t.Fatal("awake-time expiry was disabled")
	}
}

func TestPowerResumeGraceCannotResurrectExpiredEngine(t *testing.T) {
	table := flows.New(flows.Defaults(), nil)
	s := New(&runtimeFake{table: table}, table, nil)
	now := time.Unix(100, 0)
	s.now = func() time.Time { return now }
	call(t, s, Request{ID: "attach", Method: "attach", Instance: s.Instance})
	now = now.Add(29 * time.Second)
	s.Resume()
	now = now.Add(9 * time.Second)
	if s.Expired() {
		t.Fatal("resume did not grant a renewal opportunity")
	}
	call(t, s, Request{ID: "renew", Method: "renew", Instance: s.Instance, Epoch: 1})
	now = now.Add(Lease)
	if !s.Expired() {
		t.Fatal("missing expiry precondition")
	}
	s.Resume()
	if reply := s.Handle(context.Background(), Request{ID: "renew", Method: "renew", Instance: s.Instance, Epoch: 1}); reply.Error == "" {
		t.Fatal("resume resurrected an engine already cleaning up")
	}
}

func TestNativeLeaseClockAdvances(t *testing.T) {
	before := leaseNow()
	time.Sleep(20 * time.Millisecond)
	elapsed := leaseNow().Sub(before)
	if elapsed <= 0 || elapsed > time.Second {
		t.Fatal("lease clock unavailable or invalid", elapsed)
	}
}
