//go:build windows

package winengine

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

// A harness adapter with no LUID history is judged by its row's own LUID.
func TestLeftoverAdapterPresenceUsesPnPAndIPNotTheRow(t *testing.T) {
	guid, alias := "{E66D91A5-76B7-4A95-95CB-E2D87706E994}", "TestISP"
	gone := func() (bool, error) { return false, nil }
	there := func() (bool, error) { return true, nil }
	noIP := func(uint64, uint16) error { return windows.ERROR_NOT_FOUND }
	ipFor := func(luid uint64) func(uint64, uint16) error {
		return func(l uint64, family uint16) error {
			if l == luid && family == windows.AF_INET {
				return nil
			}
			return windows.ERROR_FILE_NOT_FOUND
		}
	}
	row := adapterRow{guid: guid, alias: alias, luid: 77}
	for _, tc := range []struct {
		name    string
		rows    []adapterRow
		pnp     func() (bool, error)
		ip      func(uint64, uint16) error
		present bool
		failed  bool
	}{
		{"nothing-at-all", nil, gone, noIP, false, false},
		{"lingering-row-only", []adapterRow{row}, gone, noIP, false, false},
		{"row-with-pnp-device", []adapterRow{row}, there, noIP, true, false},
		{"row-with-ip-interface", []adapterRow{row}, gone, ipFor(77), true, false},
		{"other-luid-ip-does-not-count", []adapterRow{row}, gone, ipFor(78), false, false},
		{"pnp-without-row", nil, there, noIP, true, false},
		{"foreign-guid-under-our-alias", []adapterRow{{guid: "{00000000-1111-2222-3333-444444444444}", alias: alias, luid: 5}}, gone, noIP, true, true},
		{"query-error-counts-as-present", []adapterRow{row}, func() (bool, error) { return false, errors.New("setupapi") }, noIP, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			present, err := leftoverAdapterPresent(guid, alias, tc.rows, tc.pnp, tc.ip)
			if present != tc.present || (err != nil) != tc.failed {
				t.Fatal(present, err)
			}
		})
	}
}
