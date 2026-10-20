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
