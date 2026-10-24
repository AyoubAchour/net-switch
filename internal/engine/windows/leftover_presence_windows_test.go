//go:build windows

package winengine

import (
	"errors"
	"strings"
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
		reason  string
	}{
		{"nothing-at-all", nil, gone, noIP, false, false, "no row"},
		{"lingering-row-only", []adapterRow{row}, gone, noIP, false, false, "lingering interface row (luid 77)"},
		{"row-with-pnp-device", []adapterRow{row}, there, noIP, true, false, "PnP devnode"},
		{"row-with-ip-interface", []adapterRow{row}, gone, ipFor(77), true, false, "IP interface family 2 still exists for luid 77"},
		{"other-luid-ip-does-not-count", []adapterRow{row}, gone, ipFor(78), false, false, "lingering interface row"},
		{"pnp-without-row", nil, there, noIP, true, false, "PnP devnode"},
		{"foreign-guid-under-our-alias", []adapterRow{{guid: "{00000000-1111-2222-3333-444444444444}", alias: alias, luid: 5}}, gone, noIP, true, true, "foreign adapter {00000000-1111-2222-3333-444444444444}"},
		{"query-error-counts-as-present", []adapterRow{row}, func() (bool, error) { return false, errors.New("setupapi") }, noIP, true, true, "PnP query"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			present, reason, err := leftoverAdapterPresent(guid, alias, tc.rows, tc.pnp, tc.ip)
			if present != tc.present || (err != nil) != tc.failed || !strings.Contains(reason, tc.reason) {
				t.Fatal(present, reason, err)
			}
		})
	}
}
