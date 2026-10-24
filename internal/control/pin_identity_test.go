package control

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/control/engine"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
)

// End to end inside Control: a tracked sandbox app carries the engine's
// identity, the pin API stores that identity, the revision carries it, and the
// state shows the identity; a stale path pin is kept, shown and flagged.
func TestPinFromTrackedSandboxAppStoresTheEngineIdentity(t *testing.T) {
	c, e, _, _ := testCore(t, map[string]any{"lines": testLines()})
	ctx := context.Background()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	flow := engine.Connection{}
	flow.ID = "1"
	flow.Metadata.ProcessPath = "/snap/foo/123/bin/foo"
	flow.AppID = "snap:foo"
	flow.Chains = []string{"line-a1"}
	flow.Start = c.op.Clock.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	e.connections = []engine.Connection{flow}
	if err := c.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if got := c.tracker.IdentityOf(apps.AppKey("/snap/foo/123/bin/foo")); got != "snap:foo" {
		t.Fatal("tracked app lost the engine identity", got)
	}
	if _, err := c.Action(ctx, "POST", "/api/app-line", map[string]any{"path": "/snap/foo/123/bin/foo", "line": "b2"}); err != nil {
		t.Fatal(err)
	}
	pins := c.pinsLocked()
	if len(pins) != 1 || pins[0].Path != "snap:foo" || pins[0].LineID != "b2" {
		t.Fatalf("pin did not store the selected identity: %+v", pins)
	}
	if p := e.Snapshot().Policy.AppLines; len(p) != 1 || p[0].Path != "snap:foo" {
		t.Fatalf("revision did not carry the identity pin: %+v", p)
	}
	state := stateRows(t, c)
	row := state[apps.AppKey("/snap/foo/123/bin/foo")]
	if row == nil || row["identity"] != "snap:foo" || js.Text(row["line"]) != "b2" || row["pinNeedsReselection"] != nil {
		t.Fatalf("state row for the tracked snap: %+v", row)
	}
	// Repinning or unpinning through the path replaces that identity pin.
	if _, err := c.Action(ctx, "POST", "/api/app-line", map[string]any{"path": "/snap/foo/123/bin/foo", "line": nil}); err != nil {
		t.Fatal(err)
	}
	if len(c.pinsLocked()) != 0 {
		t.Fatalf("identity pin survived unpinning by path: %+v", c.pinsLocked())
	}
	// A path pin stored for a sandboxed app (never written by this code; it
	// could only predate it) is kept and shown as needing reselection.
	if err := c.save(map[string]any{"appLines": apps.Pins{{Path: "/snap/foo/123/bin/foo", LineID: "b2"}}}); err != nil {
		t.Fatal(err)
	}
	row = stateRows(t, c)[apps.AppKey("/snap/foo/123/bin/foo")]
	if row == nil || row["pinNeedsReselection"] != true || js.Text(row["line"]) != "b2" {
		t.Fatalf("stale sandbox path pin not flagged: %+v", row)
	}
	// Windows and plain rows keep their shape: no identity, no flag.
	if plain := stateRows(t, c)[apps.AppKey(`C:\Apps\Main.exe`)]; plain != nil {
		t.Fatal("unexpected row", plain)
	}
}

func stateRows(t *testing.T, c *Core) map[string]map[string]any {
	t.Helper()
	b, err := json.Marshal(c.State())
	if err != nil {
		t.Fatal(err)
	}
	var state struct {
		Apps []map[string]any `json:"apps"`
	}
	if err := json.Unmarshal(b, &state); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, row := range state.Apps {
		out[js.Text(row["key"])] = row
	}
	return out
}
