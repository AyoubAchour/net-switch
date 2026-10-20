//go:build windows

package winengine

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/journal"
)

type removalTestStore struct {
	*journal.FileStore
	before func() error
}

func (s removalTestStore) AppendBatch(records []journal.Record) error {
	if records[0].Phase == "removed" {
		if err := s.before(); err != nil {
			return err
		}
	}
	return s.FileStore.AppendBatch(records)
}

func TestWindowsRemovedMarksFollowNativeCommit(t *testing.T) {
	for _, stopAt := range []string{"native commit", "removed mark", "complete"} {
		t.Run(stopAt, func(t *testing.T) {
			disk := &journal.FileStore{Path: filepath.Join(t.TempDir(), "journal"), SyncParent: func(string) error { return nil }}
			intent := journal.Record{ID: "owned", Boot: "boot", Instance: "instance", Kind: "wfp-filter",
				Fingerprint: journal.Fingerprint{"key": "owned-filter"}, Phase: "intent"}
			if err := disk.Append(intent); err != nil {
				t.Fatal(err)
			}
			nativePresent, markAttempted := true, false
			cut := errors.New("crash boundary")
			store := measuredJournalStore{
				Store: removalTestStore{FileStore: disk, before: func() error {
					markAttempted = true
					if nativePresent {
						t.Fatal("removed mark preceded the native deletion commit")
					}
					if stopAt == "removed mark" {
						return cut
					}
					return nil
				}},
				beforeRemoved: func() error {
					if stopAt == "native commit" {
						return cut
					}
					nativePresent = false
					return nil
				},
			}
			removed := intent
			removed.Phase = "removed"
			err := store.AppendBatch([]journal.Record{removed})
			records, readErr := disk.Records()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if stopAt == "complete" {
				if err != nil || nativePresent || len(records) != 2 || records[1].Phase != "removed" {
					t.Fatalf("completed cleanup: native=%t records=%v error=%v", nativePresent, records, err)
				}
			} else {
				if !errors.Is(err, cut) || len(records) != 1 || records[0].Phase != "intent" {
					t.Fatalf("crash lost recovery ownership: native=%t records=%v error=%v", nativePresent, records, err)
				}
				if stopAt == "native commit" && (!nativePresent || markAttempted) {
					t.Fatal("failed native transaction advanced the durable journal")
				}
				// A subsequent cleanup still has the original intent. It may
				// fingerprint-delete a present object or skip an absent one.
				nativePresent = false
				if err := disk.Append(removed); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
