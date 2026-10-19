package settings

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestJournalSyncCompletesBeforeAtomicReplacement(t *testing.T) {
	dir := t.TempDir()
	fail := false
	count := 0
	store := New(dir, Options{FileName: "control-journal.json", Defaults: map[string]any{"revision": float64(0)}, SyncFile: func(path string) error {
		count++
		if !strings.HasSuffix(path, ".tmp") {
			t.Fatalf("sync did not target temporary file: %s", path)
		}
		if fail {
			return errors.New("flush failed")
		}
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		return f.Sync()
	}})
	if _, err := store.Update(map[string]any{"revision": float64(1)}); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("journal and backup sync count %d", count)
	}
	fail = true
	if _, err := store.Update(map[string]any{"revision": float64(2)}); err == nil || !strings.Contains(err.Error(), "flush failed") {
		t.Fatal(err)
	}
	if store.Values()["revision"] != float64(1) {
		t.Fatal("unflushed revision published")
	}
	reopened := New(dir, Options{FileName: "control-journal.json", Defaults: map[string]any{"revision": float64(0)}})
	if value, err := reopened.Load(); err != nil || value["revision"] != float64(1) {
		t.Fatal(value, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			t.Fatal("failed sync left a temporary file")
		}
	}
}
