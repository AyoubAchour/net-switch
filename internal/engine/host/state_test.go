package host

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/policy"
)

func TestNativeStateSerializesEpochAndRevisionWithoutPersistingPoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	save := func(r Record) error {
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		return os.WriteFile(path, b, 0600)
	}
	d, err := Open(path, "first", save)
	if err != nil {
		t.Fatal(err)
	}
	var work sync.WaitGroup
	work.Go(func() {
		for n := uint64(1); n <= 100; n++ {
			if err := d.SaveEpoch(n); err != nil {
				t.Error(err)
				return
			}
		}
	})
	work.Go(func() {
		for n := uint64(1); n <= 100; n++ {
			if err := d.SaveApplied(policy.Applied{N: n, Hash: "hash", Point: 999}); err != nil {
				t.Error(err)
				return
			}
		}
	})
	work.Wait()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["epoch"] != float64(100) || fields["n"] != float64(100) || fields["point"] != nil {
		t.Fatal(string(b))
	}
	other, err := Open(path, "second", save)
	if err != nil || other.InitialEpoch() != 100 {
		t.Fatal(other, err)
	}
	if err := other.SaveEpoch(100); err == nil {
		t.Fatal("old epoch accepted")
	}
	if err := other.SaveEpoch(101); err != nil {
		t.Fatal(err)
	}
	var record Record
	b, _ = os.ReadFile(path)
	if err := json.Unmarshal(b, &record); err != nil || record.Instance != "second" || record.N != 100 {
		t.Fatal(record, err)
	}
}

func TestNativeStateFailedWriteDoesNotAcknowledgeOrOverwriteOtherFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	fail := false
	var saved Record
	d, err := Open(path, "instance", func(r Record) error {
		if fail {
			return errors.New("disk full")
		}
		saved = r
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	fail = true
	if d.SaveEpoch(1) == nil || d.SaveApplied(policy.Applied{N: 1}) == nil || d.InitialEpoch() != 0 {
		t.Fatal("failed commit was published")
	}
	fail = false
	if err := d.SaveEpoch(1); err != nil {
		t.Fatal(err)
	}
	if saved.N != 0 {
		t.Fatal("failed revision survived a later epoch save")
	}
	if err := d.SaveApplied(policy.Applied{N: 2, Hash: "ok"}); err != nil {
		t.Fatal(err)
	}
	if saved.Epoch != 1 || saved.N != 2 {
		t.Fatal(saved)
	}
}

func TestNativeStateRejectsCorruptAndStandInRecords(t *testing.T) {
	for _, content := range []string{"{", `{"engineInstanceId":"old","appliedRevision":{"n":1}}`, `{"schema":2}`} {
		path := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := Open(path, "new", func(Record) error { t.Fatal("invalid state was replaced"); return nil })
		if err == nil {
			t.Fatal("invalid state accepted", content)
		}
	}
}
