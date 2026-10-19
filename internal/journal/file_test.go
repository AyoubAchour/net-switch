package journal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileTailRecoveryAndCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine-journal.json")
	syncs := 0
	store := &FileStore{Path: path, SyncParent: func(string) error { syncs++; return nil }}
	r := Record{ID: "1", Boot: "boot", Instance: "engine", Kind: "route", Phase: "intent", Fingerprint: fingerprint()}
	if err := store.Append(r); err != nil {
		t.Fatal(err)
	}
	if syncs != 1 {
		t.Fatal("parent durability missing")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	file.Write([]byte(`{"torn`))
	file.Close()
	records, err := store.Records()
	if err != nil || len(records) != 1 {
		t.Fatal("torn tail recovery", err)
	}
	r.Phase = "created"
	if err := store.Append(r); err != nil {
		t.Fatal(err)
	}
	records, err = store.Records()
	if err != nil || len(records) != 2 {
		t.Fatal(err)
	}
	file, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	file.Write([]byte("{\"record\":{},\"sha256\":\"wrong\"}\n"))
	file.Close()
	if records, err := store.Records(); err != nil || len(records) != 2 {
		t.Fatal("garbled final line was not recovered", err)
	}
	file, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	file.Write([]byte("garbled\nanother line\n"))
	file.Close()
	if _, err := store.Records(); err == nil {
		t.Fatal("interior corruption silently ignored")
	}
}
