package lifecycle

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/host"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/settings"
)

func TestNativeHistoryDoesNotDependOnAnUnusableBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine-state.json")
	if err := os.Mkdir(path+".bak", 0700); err != nil {
		t.Fatal(err)
	}
	store, err := host.Open(path, "instance", func(record host.Record) error { return saveNativeWith(path, record, settings.Options{}) })
	if err != nil {
		t.Fatal("unusable backup prevented startup", err)
	}
	if err := store.SaveEpoch(1); err != nil {
		t.Fatal("unusable backup prevented attach", err)
	}
	if err := store.SaveApplied(policy.Applied{N: 1, Hash: "policy"}); err != nil {
		t.Fatal("unusable backup prevented apply", err)
	}
	record, err := host.ReadRecord(path)
	if err != nil || record.Epoch != 1 || record.N != 1 {
		t.Fatal(record, err)
	}
}
