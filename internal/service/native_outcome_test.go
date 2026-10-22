package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/host"
)

func TestNativeStatusRequiresMatchingSuccessfulRecovery(t *testing.T) {
	dir := t.TempDir()
	instance := strings.Repeat("a", 32)
	write := func(path string, v any) {
		t.Helper()
		b, _ := json.Marshal(v)
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, "engine-state.json"), host.Record{Schema: 1, Instance: instance})
	path, err := host.OutcomePath(dir, instance)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		state   string
		main    uint32
		manager string
		known   bool
		code    uint32
	}{
		{"pending", 3, "", false, 3}, {"failed", 3, "", true, 1}, {"complete", 3, "exit-code", true, 3},
		{"complete", 0, "success", true, 0}, {"complete", 0, "exit-code", true, 1},
	} {
		outcome := host.Outcome{Instance: instance, State: tc.state}
		if tc.state == "failed" {
			outcome.Error = "cleanup evidence"
		}
		write(path, outcome)
		got := readNativeOutcome(dir, Status{Stopped: true, ExitKnown: true, ExitCode: tc.main, ManagerResult: tc.manager}, nil)
		if got.ExitKnown != tc.known || got.ExitCode != tc.code || got.MainExitCode != tc.main {
			t.Fatal(tc, got)
		}
	}
	write(path, host.Outcome{Instance: strings.Repeat("b", 32), State: "complete"})
	if got := readNativeOutcome(dir, Status{Stopped: true, ExitKnown: true, ExitCode: 3}, nil); got.ExitKnown {
		t.Fatal("foreign outcome proved a clean loss", got)
	}
}
