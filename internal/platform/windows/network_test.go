package winplatform

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewArguments(t *testing.T) {
	for _, args := range [][]string{
		{"network", "--once"}, {"network", "--parent", "123"},
		{"probe", "--interface-index", "3", "--targets", "1.1.1.1:443,8.8.8.8:443"},
		{"policy"},
	} {
		if _, err := parseArgs(args); err != nil {
			t.Errorf("%v: %v", args, err)
		}
	}
	for _, args := range [][]string{
		{"probe", "--interface-index", "0", "--targets", "1.1.1.1:443"},
		{"probe", "--interface-index", "1", "--targets", "example.com:443"},
		{"probe", "--interface-index", "1", "--targets", "[::1]:443"},
		{"probe", "--interface-index", "1", "--targets", "1.1.1.1:0"},
		{"probe", "--interface-index", "1", "--targets", "1.1.1.1:443", "--timeout-ms", "0"},
	} {
		if _, err := parseArgs(args); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
}

func TestFirstSuccessfulProbeCancelsTheOther(t *testing.T) {
	cancelled := make(chan struct{})
	result := raceProbes(context.Background(), []string{"slow", "fast"}, func(ctx context.Context, target string) error {
		if target == "fast" {
			return nil
		}
		<-ctx.Done()
		close(cancelled)
		return ctx.Err()
	})
	if !result.OK || result.Target != "fast" || result.MS < 1 {
		t.Fatalf("%+v", result)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("the losing probe wasn't cancelled")
	}
	result = raceProbes(context.Background(), []string{"a", "b"}, func(context.Context, string) error { return errors.New("refused") })
	if result.OK || !strings.Contains(result.Error, "a: refused") || !strings.Contains(result.Error, "b: refused") {
		t.Fatalf("%+v", result)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result = raceProbes(ctx, []string{"a"}, func(ctx context.Context, _ string) error { <-ctx.Done(); return ctx.Err() })
	if result.OK || result.Error == "" {
		t.Fatalf("%+v", result)
	}
}

func TestNetworkCoalescesBurstsAndStillRefreshesWhenQuiet(t *testing.T) {
	changed := make(chan struct{}, 100)
	emitted := make(chan time.Time, 10)
	done := make(chan error, 1)
	stop := errors.New("reader closed")
	go func() {
		calls := 0
		done <- streamNetwork(changed, func() error {
			calls++
			emitted <- time.Now()
			if calls == 3 {
				return stop
			}
			return nil
		}, 150*time.Millisecond, 30*time.Millisecond)
	}()
	start := <-emitted
	for range 100 {
		changed <- struct{}{}
	}
	burst := <-emitted
	if burst.Sub(start) < 20*time.Millisecond {
		t.Fatal("burst wasn't coalesced")
	}
	refresh := <-emitted
	if refresh.Sub(start) < 100*time.Millisecond {
		t.Fatal("burst generated extra snapshots")
	}
	if err := <-done; !errors.Is(err, stop) {
		t.Fatalf("write failure wasn't propagated: %v", err)
	}
}

func TestNetworkRetriesReadFailureWithoutExiting(t *testing.T) {
	stop := errors.New("output closed")
	calls := 0
	started := time.Now()
	err := streamNetwork(make(chan struct{}), func() error {
		calls++
		if calls < 3 {
			return &networkReadError{errors.New("access denied")}
		}
		return stop
	}, time.Hour, time.Millisecond)
	if !errors.Is(err, stop) || calls != 3 || time.Since(started) < 1500*time.Millisecond {
		t.Fatalf("calls=%d elapsed=%s err=%v", calls, time.Since(started), err)
	}
}
