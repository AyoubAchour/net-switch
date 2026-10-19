package control

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/updates"
)

func TestFailedUpdateCheckKeepsSettingsResponseSuccessful(t *testing.T) {
	c, _, _, files := testCore(t, map[string]any{})
	c.op.CheckUpdate = func(context.Context) (*updates.Offer, error) { return nil, errors.New("offline") }
	for i := 0; i < 2; i++ {
		if _, err := c.Action(context.Background(), "POST", "/api/settings", map[string]any{"checkForUpdates": true}); err != nil {
			t.Fatalf("saved settings failed because an update check failed: %v", err)
		}
	}
	count := 0
	for _, line := range files.logs {
		if strings.Contains(line, "could not check for updates: offline") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected one diagnostic for repeated failure, got %d", count)
	}
}

func TestConcurrentUpdateChecksShareOneResult(t *testing.T) {
	c, _, _, _ := testCore(t, map[string]any{"checkForUpdates": true})
	entered, release := make(chan struct{}, 2), make(chan struct{})
	var calls atomic.Int32
	c.op.CheckUpdate = func(context.Context) (*updates.Offer, error) {
		calls.Add(1)
		entered <- struct{}{}
		<-release
		return &updates.Offer{Version: "1.0.0"}, nil
	}
	done := make(chan string, 2)
	go func() { result, _ := c.CheckUpdate(context.Background(), false); done <- result }()
	<-entered
	go func() { result, _ := c.CheckUpdate(context.Background(), true); done <- result }()
	select {
	case <-entered:
		t.Error("overlapping checks started two requests")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	for i := 0; i < 2; i++ {
		if got := <-done; got != "available" {
			t.Errorf("result %q", got)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("network calls %d", calls.Load())
	}
}
