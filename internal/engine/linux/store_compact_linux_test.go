//go:build linux

package linux

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/journal"
)

func TestJournalCompactionRetainsLiveIntentAndCreatedState(t *testing.T) {
	dir := t.TempDir()
	store := diskStore{filepath.Join(dir, "journal")}
	for i := range 100 {
		r := journal.Record{ID: strconv.Itoa(i), Boot: "boot", Instance: "engine", Kind: "binding", Fingerprint: journal.Fingerprint{"object": "test"}, Phase: "intent"}
		phases := []string{"intent", "created", "removed"}
		if i == 98 {
			phases = []string{"intent"}
		}
		if i == 99 {
			phases = []string{"intent", "created"}
		}
		for _, phase := range phases {
			r.Phase = phase
			if err := store.Append(r); err != nil {
				t.Fatal(err)
			}
		}
	}
	before, err := os.Stat(store.path)
	if err != nil || before.Size() < 10000 {
		t.Fatalf("journal was not large before compaction: %v %v", before, err)
	}
	j := &journal.Journal{Store: store, Lock: fileLock{filepath.Join(dir, "lock")}}
	s, err := j.Open(context.Background(), "boot", "engine")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Compact(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := store.Records()
	if err != nil || len(records) != 3 || records[0].ID != "98" || records[0].Phase != "intent" || records[1].ID != "99" || records[1].Phase != "intent" || records[2].ID != "99" || records[2].Phase != "created" {
		t.Fatalf("live crash-recovery states changed: %+v %v", records, err)
	}
	after, err := os.Stat(store.path)
	if err != nil || after.Size() >= before.Size()/10 {
		t.Fatalf("compaction did not shrink log: %v %v", after, err)
	}
	reopened, err := j.Open(context.Background(), "boot", "recovery")
	if err != nil {
		t.Fatalf("compacted journal did not reopen: %v", err)
	}
	reopened.Close()
}
