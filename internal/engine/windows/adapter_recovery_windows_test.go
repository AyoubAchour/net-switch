//go:build windows

package winengine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/journal"
	"github.com/AyoubAchour/net-switch/internal/wintun"
	"golang.org/x/sys/windows"
)

type interruptedAdapter struct {
	*checkpointObjects
	store      *diskJournal
	recovering bool
}

func (d *interruptedAdapter) Create(ctx context.Context, fp journal.Fingerprint) error {
	if err := d.checkpointObjects.Create(ctx, fp); err != nil {
		return err
	}
	return errors.New("process died after adapter create, before LUID save")
}
func (d *interruptedAdapter) Remove(ctx context.Context, fp journal.Fingerprint) error {
	if !d.recovering {
		return errors.New("test must reopen journal for recovery")
	}
	prior, err := d.store.adapterHistory("boot")
	if err != nil {
		return err
	}
	luid, present, err := recoveredAdapterLUID(wintun.DefaultGUID, "NetSwitch", prior,
		[]adapterRow{{wintun.DefaultGUID, "NetSwitch", 77}},
		func() (bool, error) { return true, nil }, func(uint64, uint16) error { return nil })
	if err != nil || luid != 77 || !present {
		return errors.New("journal did not recover adapter identity")
	}
	if err := d.store.saveAdapterHistory("boot", luid); err != nil {
		return err
	}
	return d.checkpointObjects.Remove(ctx, fp)
}

func TestAdapterIntentRecoversBeforeHistoryWasSaved(t *testing.T) {
	for _, prior := range []uint64{0, 12, 77} {
		store := newDiskJournal(filepath.Join(t.TempDir(), "journal"))
		if prior != 0 {
			if err := store.saveAdapterHistory("boot", prior); err != nil {
				t.Fatal(err)
			}
		}
		d := &interruptedAdapter{checkpointObjects: &checkpointObjects{live: map[string]journal.Fingerprint{}}, store: store}
		j := &journal.Journal{Store: store, Lock: checkpointLock{}, Kinds: map[string]journal.Object{"adapter": d}}
		s, err := j.Open(context.Background(), "boot", "crashed")
		if err != nil {
			t.Fatal(err)
		}
		if s.Create(context.Background(), "adapter", journal.Fingerprint{"name": "NetSwitch", "guid": wintun.DefaultGUID}) == nil {
			t.Fatal("missing injected crash")
		}
		records, err := store.Records()
		if err != nil || len(records) != 1 || records[0].Phase != "intent" || len(d.live) != 1 {
			t.Fatal("crash precondition", records, err)
		}
		s.Close()
		d.recovering = true
		recovered, err := j.Open(context.Background(), "boot", "recovery")
		if err != nil {
			t.Fatal(err)
		}
		if err := recovered.Cleanup(context.Background()); err != nil {
			t.Fatal(err)
		}
		recovered.Close()
		records, err = store.Records()
		if err != nil || len(records) != 0 || len(d.live) != 0 {
			t.Fatal("recovery left adapter or intent", records, err)
		}
		if luid, err := store.adapterHistory("boot"); err != nil || luid != 77 {
			t.Fatal("recovery did not retain adopted identity", luid, err)
		}
	}
}

func TestAdapterRecoveryOnlyAdoptsVerifiedIdentity(t *testing.T) {
	rows := []adapterRow{{wintun.DefaultGUID, "NetSwitch", 77}}
	for _, tc := range []struct {
		name             string
		rows             []adapterRow
		present          bool
		deviceErr, ipErr error
		wantErr          bool
	}{
		{"retired-row", rows, false, nil, windows.ERROR_FILE_NOT_FOUND, false},
		{"live-ip-no-device", rows, false, nil, nil, true},
		{"unverified-device", rows, true, windows.ERROR_ACCESS_DENIED, nil, true},
		{"foreign-alias", []adapterRow{{"foreign", "NetSwitch", 77}}, true, nil, nil, true},
		{"ambiguous", append(append([]adapterRow{}, rows...), adapterRow{wintun.DefaultGUID, "NetSwitch", 78}), true, nil, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := recoveredAdapterLUID(wintun.DefaultGUID, "NetSwitch", 0, tc.rows, func() (bool, error) { return tc.present, tc.deviceErr }, func(uint64, uint16) error { return tc.ipErr })
			if (err != nil) != tc.wantErr {
				t.Fatal(err)
			}
		})
	}
	// The ordinary guard must still reject the same row without recorded identity.
	if present, err := adapterPresent(wintun.DefaultGUID, "NetSwitch", 0, rows, func() (bool, error) { return true, nil }, func(uint64, uint16) error { return nil }); !present || err == nil {
		t.Fatal("create guard adopted recovery identity")
	}
}

func TestCorruptAdapterHistoryIsReplaced(t *testing.T) {
	store := newDiskJournal(filepath.Join(t.TempDir(), "journal"))
	if err := os.WriteFile(store.file.Path+".adapter", []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if luid, err := store.adapterHistory("boot"); luid != 0 || err != nil {
		t.Fatal(luid, err)
	}
	if err := store.saveAdapterHistory("boot", 77); err != nil {
		t.Fatal(err)
	}
	if luid, err := store.adapterHistory("boot"); luid != 77 || err != nil {
		t.Fatal(luid, err)
	}
}

func TestAdapterHistoryFailureDoesNotAdvanceMemory(t *testing.T) {
	o := &objects{adapterLUID: 7, saveAdapterLUID: func(uint64) error { return errors.New("disk failure") }}
	if o.rememberAdapter(77) == nil || o.adapterLUID != 7 {
		t.Fatal("failed persistence advanced remembered identity")
	}
}
