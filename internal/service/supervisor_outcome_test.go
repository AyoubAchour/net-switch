package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/host"
)

func TestNativeHostOutcomeNeverPromotesRawChildZero(t *testing.T) {
	dir := t.TempDir()
	id := strings.Repeat("e", 32)
	write := func(path string, v any) {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, "engine-state.json"), host.Record{Schema: 1, Instance: id})
	path, err := host.OutcomePath(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	for _, main := range []uint32{0, 1, 3} {
		write(path, host.Outcome{Instance: id, State: "complete", Child: &host.ChildOutcome{PID: 10, Code: 0, Completed: false}})
		got := readNativeOutcome(dir, Status{Stopped: true, ExitKnown: true, ExitCode: main}, nil)
		if !got.ExitKnown || got.ExitCode != 1 {
			t.Fatal("incomplete raw zero became clean", main, got)
		}
	}
}
