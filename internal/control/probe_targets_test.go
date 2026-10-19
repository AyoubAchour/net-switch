package control

import (
	"context"
	"sync"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/settings"
)

func TestExplicitLegacyPairReplacesAllDefaultOperators(t *testing.T) {
	c, e, clock, files := testCore(t, map[string]any{"lines": testLines()})
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	files.fail = true
	if _, err := c.Action(context.Background(), "POST", "/api/settings", map[string]any{"probeTargets": []any{"1.1.1.1:443", "8.8.8.8:443"}}); err == nil {
		t.Fatal("failed save reported success")
	}
	if c.values["probeTargetsCustom"] == true {
		t.Fatal("failed save published the override")
	}
	files.fail = false
	if _, err := c.Action(context.Background(), "POST", "/api/settings", map[string]any{"probeTargets": []any{"1.1.1.1:443", "8.8.8.8:443"}}); err != nil {
		t.Fatal(err)
	}
	reopened := settings.New("/test", c.op.IO)
	if _, err := reopened.Load(); err != nil {
		t.Fatal(err)
	}
	values := reopened.Values()
	if len(probeTargets(values["probeTargets"], values["probeTargetsCustom"] == true)) != 2 {
		t.Fatal("explicit choice was lost on reopening settings")
	}
	var mu sync.Mutex
	seen := map[string]bool{}
	e.probe = func(r engine.ProbeRequest) engine.ProbeResult {
		mu.Lock()
		seen[r.Target] = true
		mu.Unlock()
		return engine.ProbeResult{Outcome: engine.LineFailed}
	}
	clock.advance(15000)
	c.scheduleProbes(context.Background(), nil)
	if len(seen) != 2 || !seen["1.1.1.1:443"] || !seen["8.8.8.8:443"] {
		t.Fatalf("explicit targets were replaced with defaults: %v", seen)
	}
}
