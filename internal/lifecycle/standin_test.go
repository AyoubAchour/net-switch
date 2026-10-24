package lifecycle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/journal"
)

// The pre-release stand-in build left engine-state.json without the native
// schema and adapter-scope records in the journal. Both the installer and the
// native host refuse such a folder with one clear message; a native folder and
// an empty folder pass. On main nothing checked this.
func TestStandInStoreIsRefused(t *testing.T) {
	empty := t.TempDir()
	if err := refuseStandInStore(empty); err != nil {
		t.Fatal("empty folder refused", err)
	}
	standIn := t.TempDir()
	if err := os.WriteFile(filepath.Join(standIn, "engine-state.json"), []byte(`{"engineInstanceId":"abc","epoch":3,"appliedRevision":null,"exitReason":"adapter-failed"}`), 0600); err != nil {
		t.Fatal(err)
	}
	err := refuseStandInStore(standIn)
	if err == nil || !strings.Contains(err.Error(), "pre-release stand-in build") || !strings.Contains(err.Error(), "engine-state.json") {
		t.Fatal("stand-in state accepted", err)
	}
	native := t.TempDir()
	if err := os.WriteFile(filepath.Join(native, "engine-state.json"), []byte(`{"schema":1,"engineInstanceId":"abc","epoch":3,"n":2,"hash":"x"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := refuseStandInStore(native); err != nil {
		t.Fatal("native folder refused", err)
	}
	scoped := t.TempDir()
	store := &journal.FileStore{Path: filepath.Join(scoped, "engine-journal.json"), SyncParent: SyncDirectory}
	if err := store.Append(journal.Record{ID: "r1", Boot: "b", Instance: "abc", Kind: "adapter-service-scope", Fingerprint: journal.Fingerprint{"service": "NetSwitchEngine"}, Phase: "created"}); err != nil {
		t.Fatal(err)
	}
	err = refuseStandInStore(scoped)
	if err == nil || !strings.Contains(err.Error(), "pre-release stand-in build") || !strings.Contains(err.Error(), "adapter-service-scope") {
		t.Fatal("stand-in journal accepted", err)
	}
	nativeJournal := t.TempDir()
	store = &journal.FileStore{Path: filepath.Join(nativeJournal, "engine-journal.json"), SyncParent: SyncDirectory}
	if err := store.Append(journal.Record{ID: "r2", Boot: "b", Instance: "abc", Kind: "wintun-adapter", Fingerprint: journal.Fingerprint{"guid": "{x}"}, Phase: "created"}); err != nil {
		t.Fatal(err)
	}
	if err := refuseStandInStore(nativeJournal); err != nil {
		t.Fatal("native journal refused", err)
	}
}
