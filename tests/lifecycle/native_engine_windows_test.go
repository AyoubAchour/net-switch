package lifecycle_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	winengine "github.com/AyoubAchour/net-switch/internal/engine/windows"
	"github.com/AyoubAchour/net-switch/internal/journal"
	"github.com/AyoubAchour/net-switch/internal/service"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func nativeImage(t *testing.T, pid uint32) string {
	t.Helper()
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	b := make([]uint16, 32768)
	size := uint32(len(b))
	if err := windows.QueryFullProcessImageName(h, 0, &b[0], &size); err != nil {
		t.Fatal(err)
	}
	return windows.UTF16ToString(b[:size])
}

func resumeNative(t *testing.T, pid uint32) {
	t.Helper()
	h, err := windows.OpenProcess(0x0800, false, pid)
	if err != nil {
		t.Error("resume native engine", err)
		return
	}
	defer windows.CloseHandle(h)
	status, _, _ := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtResumeProcess").Call(uintptr(h))
	if int32(status) < 0 {
		t.Errorf("NtResumeProcess: %#x", status)
	}
}

func assertNativeCapture(t *testing.T, _ string, fixture tunFixture) { fixture.installed(t) }

func assertNativeExitRetention(*testing.T, string, string) {} // SCM retains its stopped status.

func prepareNativeTunables(*testing.T) func(*testing.T, *nativeClient) {
	return func(*testing.T, *nativeClient) {}
}

func waitNativeCleanup(t *testing.T, fixture tunFixture, data, instance string) {
	// Read the journal only after the result written after recovery closes.
	// Holding a journal reader during its atomic checkpoint can block that
	// replacement on Windows, changing the cleanup this test observes.
	wait(t, "native recovery finishes before journal inspection", 20*time.Second, func() bool {
		state, err := service.Query(service.Engine)
		if err == nil && state.Cleanup == "failed" {
			t.Fatal("native cleanup failed", state.LastError)
		}
		return err == nil && state.Cleanup == "complete"
	})
	wait(t, "recovery retires journaled WFP objects", 20*time.Second, func() bool {
		records := nativeFirewallRecords(t, data, instance)
		if len(records) != 0 {
			return false
		}
		state, err := winengine.FirewallState()
		if err != nil {
			t.Fatal(err)
		}
		return state["sublayer"] == false && len(state["filters"].([]map[string]any)) == 0
	})
	fixture.clean(t)
}

func nativeFirewallRecords(t *testing.T, data, instance string) []journal.Record {
	t.Helper()
	file, err := os.Open(filepath.Join(data, "engine-journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, readErr := io.ReadAll(io.LimitReader(file, (16<<20)+1))
	if err := errors.Join(readErr, file.Close()); err != nil {
		t.Fatal(err)
	}
	if len(b) > 16<<20 {
		t.Fatal("native proof journal exceeds its bound")
	}
	// Do not call FileStore.Records while recovery is appending: it can repair
	// an incomplete tail. This observer must never modify what it measures.
	var records []journal.Record
	for _, line := range bytes.Split(b[:bytes.LastIndexByte(b, '\n')+1], []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var entry struct {
			Record  json.RawMessage `json:"record"`
			Records json.RawMessage `json:"records"`
			Hash    string          `json:"sha256"`
		}
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatal(err)
		}
		raw := entry.Record
		if len(entry.Records) != 0 {
			raw = entry.Records
		}
		hash := sha256.Sum256(raw)
		if len(raw) == 0 || hex.EncodeToString(hash[:]) != entry.Hash {
			t.Fatal("native journal checksum differs")
		}
		if len(entry.Records) != 0 {
			var batch []journal.Record
			if err := json.Unmarshal(raw, &batch); err != nil {
				t.Fatal(err)
			}
			records = append(records, batch...)
		} else {
			var r journal.Record
			if err := json.Unmarshal(raw, &r); err != nil {
				t.Fatal(err)
			}
			records = append(records, r)
		}
	}
	live := map[string]journal.Record{}
	for _, r := range records {
		if r.Instance != instance {
			continue
		}
		if r.Phase == "removed" {
			delete(live, r.ID)
		} else if r.Kind == "wfp-filter" || r.Kind == "wfp-sublayer" {
			live[r.ID] = r
		}
	}
	var result []journal.Record
	for _, r := range live {
		result = append(result, r)
	}
	return result
}

func assertNativeOwnedLeftovers(t *testing.T, data, instance string) {
	t.Helper()
	records := nativeFirewallRecords(t, data, instance)
	if len(records) != 4 {
		t.Fatalf("expected sublayer and three persistent filter records, got %d", len(records))
	}
	live, err := winengine.InspectFirewallRecords(records)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		if !live[r.ID] {
			t.Fatal("cleanup precondition: journaled WFP object is absent", r.Kind, r.Fingerprint["key"])
		}
	}
	t.Logf("NATIVE_LEFTOVERS instance=%s persistent_wfp=%d live_journal_records=%d", instance, len(live), len(records))
}

func nativeOwnershipIDs(t *testing.T, data, instance string) map[string]bool {
	ids := map[string]bool{}
	for _, r := range nativeFirewallRecords(t, data, instance) {
		ids[r.ID] = true
	}
	return ids
}

func pauseNativeRecovery(t *testing.T) func() {
	t.Helper()
	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(service.Engine)
	if err != nil {
		t.Fatal(err)
	}
	actions, err := s.RecoveryActions()
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.NoAction}}, 600); err != nil {
		s.Close()
		t.Fatal(err)
	}
	s.Close()
	return func() {
		m, err := mgr.Connect()
		if err != nil {
			t.Error(err)
			return
		}
		defer m.Disconnect()
		s, err := m.OpenService(service.Engine)
		if err != nil {
			t.Error(err)
			return
		}
		defer s.Close()
		if err := s.SetRecoveryActions(actions, 600); err != nil {
			t.Error(err)
		}
	}
}

func runNativeCleanup(ctx context.Context, ctl, data string) *exec.Cmd {
	return exec.CommandContext(ctx, ctl, "cleanup", "--engine", "--data", data)
}
