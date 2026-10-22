package lifecycle

import (
	"strings"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/host"
)

func TestNativeManagerExitRequiresSameInvocation(t *testing.T) {
	invocation := strings.Repeat("a", 32)
	for _, tc := range []struct {
		name, invocation, code, status, result string
		retained                               bool
	}{
		{"clean", invocation, "exited", "0", "success", true},
		{"adapter-loss", invocation, "exited", "3", "exit-code", true},
		{"crash", invocation, "killed", "KILL", "signal", true},
		{"core", invocation, "dumped", "ABRT", "core-dump", true},
		{"not-started", invocation, "", "", "resources", true},
		{"foreign", strings.Repeat("b", 32), "exited", "0", "success", false},
		{"missing-invocation", "", "exited", "0", "success", false},
		{"invalid-status", invocation, "exited", "256", "success", false},
		{"missing-status", invocation, "exited", "", "success", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := host.Outcome{InvocationID: invocation, Systemd: &host.SystemdExit{Code: "exited", Status: "0", Result: "success"}}
			env := map[string]string{"INVOCATION_ID": tc.invocation, "EXIT_CODE": tc.code, "EXIT_STATUS": tc.status, "SERVICE_RESULT": tc.result}
			captureSystemdExit(&out, func(key string) string { return env[key] })
			if (out.Systemd != nil) != tc.retained {
				t.Fatalf("retained=%t, outcome=%+v", tc.retained, out)
			}
			if out.Systemd != nil && (out.Systemd.Code != tc.code || out.Systemd.Status != tc.status || out.Systemd.Result != tc.result) {
				t.Fatal("manager result changed", out.Systemd)
			}
		})
	}
	previous := &host.SystemdExit{Code: "exited", Status: "3", Result: "exit-code"}
	out := host.Outcome{InvocationID: invocation, Systemd: previous}
	captureSystemdExit(&out, func(string) string { return "" })
	if out.Systemd != previous {
		t.Fatal("manual cleanup discarded the retained result")
	}
}
