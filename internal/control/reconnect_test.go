package control

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/control/engine"
)

func TestReconnectPersistsItsOriginalSelectionBeforeClose(t *testing.T) {
	path := `C:\Apps\Firefox.exe`
	c, e, clock, _ := testCore(t, map[string]any{"lines": testLines(), "appLines": apps.Pins{{Path: path, LineID: "b2"}}})
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	connection := engine.Connection{Connection: apps.Connection{ID: "old", Start: clock.Now().Add(-time.Minute).Format(time.RFC3339Nano), Chains: []string{"line-a1"}, Download: 100}}
	connection.Metadata.ProcessPath = path
	e.connections = []engine.Connection{connection}
	if err := c.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	var first engine.CloseRequest
	e.beforeClose = func(r engine.CloseRequest) error {
		intents, err := c.pendingClosures()
		if err != nil || len(intents) != 1 || intents[0].Purpose != "reconnect" || !reflect.DeepEqual(intents[0].Request, r) {
			t.Fatalf("close preceded persisted selection: %+v %v", intents, err)
		}
		first = r
		return errors.New("lost response")
	}
	result, err := c.reconnect(context.Background(), apps.AppKey(path))
	if err != nil || result["failed"] != 1 {
		t.Fatalf("%+v %v", result, err)
	}
	if first.StartedBefore.IsZero() || !reflect.DeepEqual(first.ConnectionIDs, []string{"old"}) {
		t.Fatal(first)
	}
	clock.advance(30000)
	connection.ID = "new"
	e.connections = append(e.connections, connection)
	e.beforeClose = func(r engine.CloseRequest) error {
		if !reflect.DeepEqual(r, first) {
			t.Fatalf("retry widened selection: %+v != %+v", r, first)
		}
		return nil
	}
	if err := c.ReplayClosures(context.Background()); err != nil {
		t.Fatal(err)
	}
	remaining, err := c.pendingClosures()
	if err != nil || len(remaining) != 0 {
		t.Fatalf("closure not acknowledged: %+v %v", remaining, err)
	}
}
