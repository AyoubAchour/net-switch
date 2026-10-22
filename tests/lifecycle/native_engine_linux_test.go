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

	"github.com/AyoubAchour/net-switch/internal/journal"
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

func assertNativeCapture(t *testing.T, _ string, _ tunFixture) {
	t.Helper()
	for _, args := range [][]string{{"link", "show", "dev", "NetSwitch"}, {"-4", "rule", "show"}} {
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
