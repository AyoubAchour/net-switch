//go:build windows

package winengine

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/wintun"
	"golang.org/x/sys/windows"
)

func TestAdapterPresenceUsesPnPAndBothIPFamilies(t *testing.T) {
	for _, tc := range []struct {
		name   string
		luid   uint64
		rows   []adapterRow
		pnp    bool
		pnpErr error
		v4, v6 error
		want   bool
	}{
		{"lingering-down-row", 7, []adapterRow{{wintun.DefaultGUID, "NetSwitch", 7}}, false, nil, windows.ERROR_NOT_FOUND, windows.ERROR_NOT_FOUND, false},
		{"row-already-gone", 7, nil, false, nil, windows.ERROR_NOT_FOUND, windows.ERROR_NOT_FOUND, false},
		{"present-pnp", 7, nil, true, nil, windows.ERROR_NOT_FOUND, windows.ERROR_NOT_FOUND, true},
		{"present-v4", 7, nil, false, nil, nil, windows.ERROR_NOT_FOUND, true},
		{"present-v6", 7, nil, false, nil, windows.ERROR_NOT_FOUND, nil, true},
		{"pnp-error", 7, nil, false, windows.ERROR_ACCESS_DENIED, windows.ERROR_NOT_FOUND, windows.ERROR_NOT_FOUND, true},
		{"v4-error", 7, nil, false, nil, windows.ERROR_INVALID_PARAMETER, windows.ERROR_NOT_FOUND, true},
		{"v6-error", 7, nil, false, nil, windows.ERROR_NOT_FOUND, windows.ERROR_ACCESS_DENIED, true},
		{"replacement-guid", 7, []adapterRow{{wintun.DefaultGUID, "NetSwitch", 8}}, false, nil, windows.ERROR_NOT_FOUND, windows.ERROR_NOT_FOUND, true},
		{"replacement-alias", 7, []adapterRow{{"foreign", "NetSwitch", 7}}, false, nil, windows.ERROR_NOT_FOUND, windows.ERROR_NOT_FOUND, true},
		{"unknown-luid", 0, []adapterRow{{wintun.DefaultGUID, "NetSwitch", 7}}, false, nil, windows.ERROR_NOT_FOUND, windows.ERROR_NOT_FOUND, true},
		{"fresh-install", 0, nil, false, nil, windows.ERROR_NOT_FOUND, windows.ERROR_NOT_FOUND, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			present, err := adapterPresent(wintun.DefaultGUID, "NetSwitch", tc.luid, tc.rows,
				func() (bool, error) { return tc.pnp, tc.pnpErr }, func(luid uint64, family uint16) error {
					calls++
					if luid != tc.luid {
						t.Fatal("wrong interface identity")
					}
					if family == windows.AF_INET {
						return tc.v4
					}
					return tc.v6
				})
			if present != tc.want || (!present && err != nil) {
				t.Fatal(present, err)
			}
			if !present && tc.luid != 0 && calls != 2 {
				t.Fatal("did not confirm both families", calls)
			}
		})
	}
}

func TestAdapterHistorySurvivesProcessAndJournalCheckpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal")
	s := newDiskJournal(path)
	if n, err := s.adapterHistory("boot"); n != 0 || err != nil {
		t.Fatal(n, err)
	}
	if err := s.saveAdapterHistory("boot", 123); err != nil {
		t.Fatal(err)
	}
	if err := s.Compact(nil); err != nil {
		t.Fatal(err)
	}
	next := newDiskJournal(path)
	if n, err := next.adapterHistory("boot"); n != 123 || err != nil {
		t.Fatal(n, err)
	}
	if n, err := next.adapterHistory("next-boot"); n != 0 || err != nil {
		t.Fatal(n, err)
	}
	next.replace = func(string, string) error { return errors.New("publish failure") }
	if next.saveAdapterHistory("boot", 456) == nil {
		t.Fatal("ignored failed identity commit")
	}
	if n, err := s.adapterHistory("boot"); n != 123 || err != nil {
		t.Fatal("failed write replaced identity", n, err)
	}
}
