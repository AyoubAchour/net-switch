package control

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/control/engine"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
)

func TestServiceJournalFailureDoesNotReachEngine(t *testing.T) {
	c, e, _, files := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	files.fail = true
	e.calls = nil
	before := c.revision
	err := c.ApplyPolicy(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not committed") {
		t.Fatal(err)
	}
	if len(e.calls) != 0 || c.revision != before {
		t.Fatal("uncommitted revision reached engine", e.calls, c.revision)
	}
}
func TestServiceRevisionPersistsSettingsAndPolicyBeforeApply(t *testing.T) {
	c, e, _, files := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	e.beforeApply = func(revision engine.Revision) {
		var saved struct {
			Desired  engine.Revision `json:"desired"`
			Settings map[string]any  `json:"settings"`
		}
		b, err := files.ReadFile(c.op.Journal.File)
		if err != nil || json.Unmarshal(b, &saved) != nil {
			t.Fatal("journal absent before engine apply", err)
		}
		if saved.Desired.Number != revision.Number || saved.Desired.Hash != revision.Hash || saved.Settings["lines"] == nil {
			t.Fatal("incomplete durable policy")
		}
	}
	if err := c.ApplyPolicy(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := c.revision
	if err := c.save(map[string]any{"combine": true}); err != nil {
		t.Fatal(err)
	}
	saved := c.op.Journal.Values()
	if js.Object(saved["settings"])["combine"] != true || c.revision <= before {
		t.Fatal("settings were not joined to a new revision")
	}
	if _, err := files.ReadFile(filepath.Join(filepath.Dir(c.op.Journal.File), "control-journal.json.bak")); err != nil {
		t.Fatal(err)
	}
}
func TestServiceSettingsMirrorFailureKeepsCommittedSettings(t *testing.T) {
	c, _, _, files := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	files.failPrefix = c.op.Settings.File + "."
	if err := c.save(map[string]any{"checkForUpdates": false}); err != nil {
		t.Fatal(err)
	}
	if c.values["checkForUpdates"] != false || js.Object(c.op.Journal.Values()["settings"])["checkForUpdates"] != false {
		t.Fatal("committed desired setting lost")
	}
	files.failPrefix = ""
	if err := c.save(map[string]any{"skippedUpdate": "1.0.1"}); err != nil {
		t.Fatal(err)
	}
	if c.op.Settings.Values()["checkForUpdates"] != false {
		t.Fatal("later mirror write lost previous committed setting")
	}
}
func TestServiceResumeHonorsCommittedStop(t *testing.T) {
	c, e, _, _ := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	c.wanted = false
	if err := c.ResumeRouting(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.wanted || e.Snapshot().Status == "on" {
		t.Fatal("Control restart reversed the owner's committed stop")
	}
}
func TestServiceCountsFailuresNotStatusObservations(t *testing.T) {
	c, _, _, _ := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	c.statusLocked(engine.Snapshot{Status: "error", FailureID: "failed-instance"})
	c.statusLocked(engine.Snapshot{Status: "starting"})
	c.statusLocked(engine.Snapshot{Status: "error", FailureID: "failed-instance"})
	if len(c.failureTimes) != 1 {
		t.Fatalf("one crash counted %d times", len(c.failureTimes))
	}
	c.statusLocked(engine.Snapshot{Status: "error", FailureID: "next-failed-attempt"})
	if len(c.failureTimes) != 2 {
		t.Fatal("a distinct failed attempt was not counted")
	}
}

func TestServiceNoLinesWaitsWithoutAnEngineAttempt(t *testing.T) {
	c, e, _, _ := testCore(t, map[string]any{"lines": []any{}})
	c.op.ServiceMode = true
	started := false
	e.beforeStart = func() { started = true }
	if err := c.Routing(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if started || len(c.failureTimes) != 0 || !c.wanted {
		t.Fatal("an empty configuration must wait for a line without consuming the failure budget")
	}
	if err := c.save(map[string]any{"lines": testLines()}); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.syncLanesLocked()
	c.mu.Unlock()
	if err := c.Supervise(context.Background()); err != nil || !started {
		t.Fatal("a configured line did not unblock the pending start", err)
	}
}

func TestSlowServiceSnapshotsDoNotRestartLiveEngine(t *testing.T) {
	c, e, _, _ := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.calls = nil
	c.monitorFailures = 50
	if err := c.Supervise(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, call := range e.calls {
		if call == "stop" || call == "start" {
			t.Fatal("flow timeout restarted healthy engine", e.calls)
		}
	}
}

func TestSecondOwnerSignInPreservesFailureBudget(t *testing.T) {
	c, _, _, _ := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	c.failureTimes = []int64{c.now()}
	if err := c.SignIn(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(c.failureTimes) != 1 {
		t.Fatal("second session erased the crash budget")
	}
}
