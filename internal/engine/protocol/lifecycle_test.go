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
