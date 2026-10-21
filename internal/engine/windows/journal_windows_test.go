//go:build windows

package winengine

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/journal"
)

type checkpointLock struct{}

func (checkpointLock) Acquire(context.Context) (func() error, error) {
	return func() error { return nil }, nil
}

type checkpointObjects struct {
	live map[string]journal.Fingerprint
	fail string
}

func (*checkpointObjects) Validate(journal.Fingerprint) error { return nil }
func (o *checkpointObjects) Inspect(_ context.Context, fp journal.Fingerprint) (journal.Fingerprint, bool, error) {
	live, found := o.live[fp["name"]]
	return maps.Clone(live), found, nil
}
func (o *checkpointObjects) Create(_ context.Context, fp journal.Fingerprint) error {
	o.live[fp["name"]] = maps.Clone(fp)
	return nil
}
func (o *checkpointObjects) Remove(_ context.Context, fp journal.Fingerprint) error {
	if o.fail == fp["name"] {
		return errors.New("interrupted object cleanup")
	}
	if maps.Equal(o.live[fp["name"]], fp) {
		delete(o.live, fp["name"])
	}
	return nil
}

func TestWindowsCheckpointRetainsLiveOwnershipAndBoundsRepeatedCycles(t *testing.T) {
	store := newDiskJournal(filepath.Join(t.TempDir(), "journal"))
	objects := &checkpointObjects{live: map[string]journal.Fingerprint{}}
	log := &journal.Journal{Store: store, Lock: checkpointLock{}, Kinds: map[string]journal.Object{"test": objects}}
	for cycle := range 20 {
		session, err := log.Open(context.Background(), "boot", "instance")
		if err != nil {
			t.Fatal(err)
		}
		if err := session.Create(context.Background(), "test", journal.Fingerprint{"name": "owned"}); err != nil {
			t.Fatal(err)
		}
		if err := session.Compact(); err != nil {
			t.Fatal(err)
		}
		session.Close()
		// Reopen a fresh session after a live checkpoint: a created record
		// without its intent would fail here instead of being silently lost.
		session, err = log.Open(context.Background(), "boot", "recovery")
		if err != nil {
			t.Fatal(err)
		}
		if len(objects.live) != 1 {
			t.Fatal("the recovery precondition did not exist")
		}
		if err := session.Cleanup(context.Background()); err != nil {
			t.Fatal(err)
		}
		session.Close()
		info, err := os.Stat(store.file.Path)
		if err != nil || info.Size() != 0 || len(objects.live) != 0 {
			t.Fatalf("cycle %d retained completed ownership: size=%v objects=%v error=%v", cycle, info, objects.live, err)
		}
	}
}

func TestWindowsCheckpointCrashBoundaries(t *testing.T) {
	for _, boundary := range []string{"before flush", "before rename", "after rename", "complete"} {
		t.Run(boundary, func(t *testing.T) {
			store := newDiskJournal(filepath.Join(t.TempDir(), "journal"))
			objects := &checkpointObjects{live: map[string]journal.Fingerprint{}}
			committed := false
			measured := measuredJournalStore{Store: store, beforeRemoved: func() error {
				committed = true
				return nil
			}}
			log := &journal.Journal{Store: compactingJournalStore{measured}, Lock: checkpointLock{},
				Kinds: map[string]journal.Object{"test": objects}}
			session, err := log.Open(context.Background(), "boot", "instance")
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			if err := session.Create(context.Background(), "test", journal.Fingerprint{"name": "owned"}); err != nil {
				t.Fatal(err)
			}
			cut := errors.New("checkpoint interruption")
			store.sync = func(file *os.File) error {
				if !committed || len(objects.live) != 0 {
					t.Fatal("checkpoint preceded committed native cleanup")
				}
				if boundary == "before flush" {
					return cut
				}
				return file.Sync()
			}
			store.replace = func(from, to string) error {
				if boundary == "before rename" {
					return cut
				}
				if err := replaceJournal(from, to); err != nil {
					return err
				}
				if boundary == "after rename" {
					return cut
				}
				return nil
			}
			err = session.Cleanup(context.Background())
			if boundary == "complete" && err != nil || boundary != "complete" && !errors.Is(err, cut) {
				t.Fatalf("boundary=%s: %v", boundary, err)
			}
			if err != nil {
				if err := session.Create(context.Background(), "test", journal.Fingerprint{"name": "fenced"}); err == nil {
					t.Fatal("checkpoint failure did not fence later mutation")
				}
			}
			// A fresh reader after each interruption gets the complete old
			// ownership log or the complete empty checkpoint, never a mixture.
			recovered := newDiskJournal(store.file.Path)
			records, err := recovered.Records()
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if boundary == "before flush" || boundary == "before rename" {
				want = 2
			}
			if len(records) != want {
				t.Fatalf("boundary=%s records=%v", boundary, records)
			}
			store.sync, store.replace = (*os.File).Sync, replaceJournal
			if err := session.Cleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWindowsInterruptedCleanupKeepsOriginalIntents(t *testing.T) {
	store := newDiskJournal(filepath.Join(t.TempDir(), "journal"))
	objects := &checkpointObjects{live: map[string]journal.Fingerprint{}}
	log := &journal.Journal{Store: store, Lock: checkpointLock{}, Kinds: map[string]journal.Object{"test": objects}}
	session, err := log.Open(context.Background(), "boot", "instance")
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	for _, name := range []string{"first", "second"} {
		if err := session.Create(context.Background(), "test", journal.Fingerprint{"name": name}); err != nil {
			t.Fatal(err)
		}
	}
	objects.fail = "first" // Reverse cleanup removes second, then stops.
	if err := session.Cleanup(context.Background()); err == nil {
		t.Fatal("interrupted cleanup passed")
	}
	records, err := store.Records()
	if err != nil || len(records) != 4 || len(objects.live) != 1 {
		t.Fatalf("partial cleanup forgot its original intents: records=%v objects=%v error=%v", records, objects.live, err)
	}
	objects.fail = ""
	if err := session.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}
