package winengine

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/journal"
)

type delayedRetirement struct {
	*checkpointObjects
	present func() (bool, error)
}

func (o delayedRetirement) Remove(ctx context.Context, fp journal.Fingerprint) error {
	if err := awaitAdapterRemoval(ctx, o.present); err != nil {
		return err
	}
	return o.checkpointObjects.Remove(ctx, fp)
}

func TestAdapterRetirementPrecedesJournalClosure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "delayed-removal", true: "replacement-refused"}[fail], func(t *testing.T) {
			store := newDiskJournal(filepath.Join(t.TempDir(), "journal"))
			objects := &checkpointObjects{live: map[string]journal.Fingerprint{}}
			polls := 0
			driver := delayedRetirement{objects, func() (bool, error) {
				polls++
				records, err := store.Records()
				if err != nil || len(records) == 0 {
					t.Fatal("ownership retired before OS absence", records, err)
				}
				if fail {
					return false, errors.New("replacement identity")
				}
				return polls < 3, nil
			}}
			log := &journal.Journal{Store: store, Lock: checkpointLock{}, Kinds: map[string]journal.Object{"adapter": driver}}
			session, err := log.Open(context.Background(), "boot", "instance")
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			fp := journal.Fingerprint{"name": "owned"}
			if err := session.Create(context.Background(), "adapter", fp); err != nil {
				t.Fatal(err)
			}
			err = session.Cleanup(context.Background())
			records, readErr := store.Records()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if fail {
				if err == nil || len(records) == 0 || len(objects.live) != 1 {
					t.Fatal("replacement lost ownership evidence", err, records)
				}
				if session.Create(context.Background(), "adapter", fp) == nil {
					t.Fatal("creation allowed after uncertain cleanup")
				}
			} else if err != nil || len(records) != 0 || len(objects.live) != 0 || polls != 3 {
				t.Fatal("retirement incomplete", err, records, polls)
			}
		})
	}
}

func TestAdapterRetirementHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	err := awaitAdapterRemoval(ctx, func() (bool, error) { cancel(); return true, nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatal("retirement ignored caller deadline", err)
	}
}
