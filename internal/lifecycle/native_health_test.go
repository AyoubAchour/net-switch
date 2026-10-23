package lifecycle

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/supervisor"
)

func TestNativeHealthLifecycleDeadlines(t *testing.T) {
	for _, state := range []string{"starting", "stopping"} {
		t.Run(state, func(t *testing.T) {
			var h nativeForwardingHealth
			now := time.Unix(100, 0)
			bound := map[string]time.Duration{"starting": nativeStartBound, "stopping": nativeStopBound}[state]
			if err := h.lifecycle(state, now); err != nil {
				t.Fatal(err)
			}
			if err := h.lifecycle(state, now.Add(bound-time.Nanosecond)); err != nil {
				t.Fatal("legitimate lifecycle operation killed", err)
			}
			var w healthWatch
			probe := healthFunc(func(context.Context) error { return h.lifecycle(state, now.Add(bound)) })
			var timeout *nativeTransitionTimeout
			if err := w.check(context.Background(), probe, func() time.Time { return now.Add(bound) }); !errors.As(err, &timeout) {
				t.Fatal("lifecycle hang was given another forwarding window", err)
			}
			if err := h.lifecycle("on", now.Add(bound)); err != nil {
				t.Fatal(err)
			}
			if err := h.lifecycle(state, now.Add(2*bound)); err != nil {
				t.Fatal("old transition deadline leaked", err)
			}
		})
	}
}

func TestNativeHealthIdleErrorSurvivesControlBackoff(t *testing.T) {
	var h nativeForwardingHealth
	now := time.Unix(100, 0)
	for second := 0; second <= 90; second++ {
		if err := h.lifecycle("error", now.Add(time.Duration(second)*time.Second)); err != nil {
			t.Fatal("idle configuration error counted as engine failure", second, err)
		}
	}
}

func TestNativeHealthRefreshesEveryForwardingGeneration(t *testing.T) {
	var h nativeForwardingHealth
	state := supervisor.Message{Index: 12, Port: 1234, Started: 1, Epoch: 1}
	calls := 0
	bind := func(index int, port uint16) error {
		calls++
		if index != state.Index || port != state.Port {
			t.Fatal("stale target")
		}
		return nil
	}
	for _, change := range []func(){func() {}, func() { state.Port++ }, func() { state.Index++ }, func() { state.Started++ }, func() { state.Epoch++ }, func() { h.index = 0; h.port = 0 }} {
		change()
		before := calls
		if err := h.target(state, bind); err != nil {
			t.Fatal(err)
		}
		if calls != before+1 {
			t.Fatal("new start did not reconnect")
		}
		if err := h.target(state, bind); err != nil || calls != before+1 {
			t.Fatal("unchanged target reconnected", err)
		}
	}
	state.Port++
	if h.target(state, func(int, uint16) error { return errors.New("bind failed") }) == nil || h.port == state.Port {
		t.Fatal("failed bind cached")
	}
}

func TestNativeHealthEighteenSecondWindow(t *testing.T) {
	now := time.Unix(100, 0)
	w := healthWatch{limit: 18 * time.Second}
	fail := healthFunc(func(context.Context) error { now = now.Add(3 * time.Second); return context.DeadlineExceeded })
	for range 5 {
		if err := w.check(context.Background(), fail, func() time.Time { return now }); err != nil {
			t.Fatal(err)
		}
	}
	if w.check(context.Background(), fail, func() time.Time { return now }) == nil {
		t.Fatal("six bounded failures did not trip")
	}
}
