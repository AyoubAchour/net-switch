package lifecycle

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/journal"
)

func TestDamagedEngineStateUsesBackup(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "engine-state.json"), []byte(`{"epoch":99,`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "engine-state.json.bak"), []byte(`{"epoch":17,"engineInstanceId":"previous"}`), 0600); err != nil {
		t.Fatal(err)
	}
	var state engineState
	logged := false
	if err := readEngineState(dir, &state, func(string) { logged = true }); err != nil || state.Epoch != 17 || state.Instance != "previous" || !logged {
		t.Fatal(state, err)
	}
}

func TestRetiredFoldersAndJournalAreRemovedByOurCleanup(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "adapter-0123456789abcdef0123456789abcdef")
	unrelated := filepath.Join(dir, "adapter-not-an-instance")
	for _, path := range []string{old, unrelated} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "engine-config.json"), []byte("retired"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(old, "engine-config.json")); err != nil {
		t.Fatal("missing leftover precondition", err)
	}
	if err := removeRetiredAdapterFolders(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("retired folder survived", err)
	}
	if _, err := os.Stat(filepath.Join(unrelated, "engine-config.json")); err != nil {
		t.Fatal("unrelated path removed", err)
	}
	store := &journal.FileStore{Path: filepath.Join(dir, "journal"), SyncParent: func(string) error { return nil }}
	record := journal.Record{ID: "old", Phase: "created"}
	if err := store.Append(record); err != nil {
		t.Fatal(err)
	}
	if err := store.ClearRetired(); err == nil {
		t.Fatal("compacted a live record")
	}
	record.Phase = "removed"
	if err := store.Append(record); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(store.Path)
	if err != nil || before.Size() == 0 {
		t.Fatal("missing journal precondition", err)
	}
	if err := store.ClearRetired(); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(store.Path)
	if err != nil || after.Size() != 0 {
		t.Fatal("retired journal grew across starts", err)
	}
}
