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

func TestNativeStatusSurvivesSystemdUnitCollection(t *testing.T) {
	dir := t.TempDir()
	instance, invocation := strings.Repeat("a", 32), strings.Repeat("b", 32)
	write := func(path string, v any) {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, "engine-state.json"), host.Record{Schema: 1, Instance: instance})
	path, err := host.OutcomePath(dir, instance)
	if err != nil {
		t.Fatal(err)
	}
	collected := Status{Stopped: true, ManagerCode: "0", ManagerStatus: "0", ManagerResult: "success"}
	for _, tc := range []struct {
		name, cleanup string
		exit          *host.SystemdExit
		known         bool
		code          uint32
	}{
		{"clean", "complete", &host.SystemdExit{Code: "exited", Status: "0", Result: "success"}, true, 0},
		{"loss", "complete", &host.SystemdExit{Code: "exited", Status: "3", Result: "exit-code"}, true, 3},
		{"crash", "complete", &host.SystemdExit{Code: "killed", Status: "KILL", Result: "signal"}, false, 0},
		{"signal-success-is-not-exit-zero", "complete", &host.SystemdExit{Code: "killed", Status: "TERM", Result: "success"}, false, 0},
		{"missing-main", "complete", nil, false, 0},
		{"missing-status", "complete", &host.SystemdExit{Code: "exited", Result: "success"}, false, 0},
		{"cleanup-pending", "pending", &host.SystemdExit{Code: "exited", Status: "0", Result: "success"}, false, 0},
		{"cleanup-failed", "failed", &host.SystemdExit{Code: "exited", Status: "3", Result: "exit-code"}, true, 1},
		{"manager-failed", "complete", &host.SystemdExit{Code: "exited", Status: "0", Result: "timeout"}, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			write(path, host.Outcome{Instance: instance, State: tc.cleanup, InvocationID: invocation, Systemd: tc.exit})
			got := readNativeOutcome(dir, collected, nil)
			if got.ExitKnown != tc.known || (got.ExitKnown && got.ExitCode != tc.code) {
				t.Fatalf("unexpected final status: %+v", got)
			}
			if !tc.known && got.LastError == "" {
				t.Fatal("unknown exit has no diagnostic", got)
			}
		})
	}
	write(path, host.Outcome{Instance: instance, State: "complete", InvocationID: invocation, Systemd: &host.SystemdExit{Code: "exited", Status: "0", Result: "success"}})
	for _, current := range []Status{
		{Stopped: true, ManagerCode: "2", ManagerStatus: "9", ManagerResult: "signal"},
		{Stopped: true, ManagerCode: "0", ManagerStatus: "0", ManagerResult: "success", ManagerInvocation: strings.Repeat("c", 32)},
		{Stopped: true, ManagerCode: "1", ManagerStatus: "3", ManagerResult: "exit-code", ExitKnown: true, ExitCode: 3},
	} {
		got := readNativeOutcome(dir, current, nil)
		if got.ExitKnown != current.ExitKnown || (got.ExitKnown && got.ExitCode != current.ExitCode) || got.MainExitSource == "systemd-stop-post" {
			t.Fatalf("stored result replaced live manager evidence: %+v -> %+v", current, got)
		}
	}
	foreign := Status{Stopped: true, ExitKnown: true, ManagerCode: "1", ManagerStatus: "0", ManagerResult: "success", ManagerInvocation: strings.Repeat("c", 32)}
	if got := readNativeOutcome(dir, foreign, nil); got.ExitKnown || got.Cleanup != "unknown" || got.LastError == "" {
		t.Fatal("new main exit combined with old invocation cleanup", got)
	}
	write(path, host.Outcome{Instance: instance, State: "complete", Systemd: &host.SystemdExit{Code: "exited", Status: "0", Result: "success"}})
	if got := readNativeOutcome(dir, collected, nil); got.ExitKnown || got.LastError == "" {
		t.Fatal("unbound result accepted", got)
	}
}
