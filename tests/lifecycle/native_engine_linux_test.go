package lifecycle_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/host"
	"github.com/AyoubAchour/net-switch/internal/journal"
	"github.com/AyoubAchour/net-switch/internal/service"
	"github.com/AyoubAchour/net-switch/tests/linux/topo"
	"golang.org/x/sys/unix"
)

func nativeImage(t *testing.T, pid uint32) string {
	t.Helper()
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func resumeNative(t *testing.T, pid uint32) {
	t.Helper()
	if err := unix.Kill(int(pid), unix.SIGCONT); err != nil {
		t.Error("resume native engine", err)
	}
}

func assertNativeCapture(t *testing.T, instance string, _ tunFixture) {
	t.Helper()
	name := nativeLinuxTun(t, instance)
	for _, args := range [][]string{{"link", "show", "dev", name}, {"-4", "rule", "show"}} {
		b, err := exec.Command("ip", append([]string{"-n", topo.DUT}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatal("native capture precondition", err, string(b))
		}
		if args[0] == "-4" && !strings.Contains(string(b), "iif lo") {
			t.Fatal("native capture rule missing", string(b))
		}
		t.Logf("NATIVE_CAPTURE %s", b)
	}
}

func waitNativeCleanup(t *testing.T, fixture tunFixture, data, instance string) {
	// systemd remains deactivating until ExecStopPost has completed, so the
	// Stopped observation in the caller already joined the cleanup command.
	fixture.clean(t)
	if len(nativeLiveRecords(t, data, instance)) != 0 {
		t.Fatal("native journal still has live records after cleanup")
	}
}

func assertNativeExitRetention(t *testing.T, data, instance string) {
	t.Helper()
	// list-units does not load the unit. Wait for actual collection so the
	// regression cannot pass just because this runner still retains its status.
	wait(t, "systemd unloads the stopped native unit", 5*time.Second, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		b, err := exec.CommandContext(ctx, "systemctl", "list-units", "--all", "--plain", "--no-legend", "netswitch-engine.service").CombinedOutput()
		if err != nil {
			t.Fatal("read loaded units", err, string(b))
		}
		return strings.TrimSpace(string(b)) == ""
	})
	state, err := service.Query(service.Engine)
	t.Logf("NATIVE_SYSTEMD_COLLECTED %+v error=%v", state, err)
	if err != nil || state.ManagerCode != "0" || state.ManagerStatus != "0" || state.ManagerInvocation != "" || !state.MainExitKnown || state.MainExitSource != "systemd-stop-post" {
		t.Fatal("manager collection did not preserve the actual main exit", state, err)
	}
	out, err := host.ReadOutcome(data, instance)
	if err != nil || out.Systemd == nil || out.Systemd.Code != "exited" || out.Systemd.Status != "0" || out.Systemd.Result != "success" {
		t.Fatal("clean exit was not recorded by matching ExecStopPost", out, err)
	}
	t.Logf("NATIVE_SYSTEMD_RETAINED invocation=%s exit=%+v", out.InvocationID, out.Systemd)
}

func nativeLiveRecords(t *testing.T, data, instance string) []journal.Record {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(data, "engine-journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	live := map[string]journal.Record{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var entry struct {
			Record journal.Record `json:"record"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatal(err)
		}
		r := entry.Record
		if r.Instance != instance {
			continue
		}
		if r.Phase == "removed" {
			delete(live, r.ID)
		} else {
			live[r.ID] = r
		}
	}
	var records []journal.Record
	for _, r := range live {
		records = append(records, r)
	}
	return records
}

func assertNativeOwnedLeftovers(t *testing.T, data, instance string) {
	t.Helper()
	records := nativeLiveRecords(t, data, instance)
	rules := 0
	for _, r := range records {
		if r.Kind == "rule" {
			rules++
		}
	}
	if rules == 0 {
		t.Fatal("cleanup precondition: no journaled native rules")
	}
	b, err := exec.Command("ip", "-n", topo.DUT, "-4", "rule", "show").CombinedOutput()
	if err != nil || !strings.Contains(string(b), "iif lo") {
		t.Fatal("cleanup precondition: native selection rule absent", err, string(b))
	}
	t.Logf("NATIVE_LEFTOVERS instance=%s rules=%d live_journal_records=%d", instance, rules, len(records))
}

func pauseNativeRecovery(t *testing.T) func() {
	t.Helper()
	dir := "/run/systemd/system/netswitch-engine.service.d"
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "native-explicit-cleanup.conf")
	if err := os.WriteFile(path, []byte("[Service]\nExecStopPost=\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if b, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		t.Fatal(err, string(b))
	}
	return func() {
		_ = os.Remove(path)
		if b, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
			t.Error(err, string(b))
		}
	}
}

func runNativeCleanup(ctx context.Context, ctl, data string) *exec.Cmd {
	return exec.CommandContext(ctx, "ip", "netns", "exec", topo.DUT, ctl, "cleanup", "--engine", "--data", data)
}
