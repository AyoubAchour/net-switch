//go:build windows

package winengine

import (
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestUDPBindRetriesAreBoundedAndCounted(t *testing.T) {
	refused := os.NewSyscallError("bind", windows.WSAENOBUFS)
	denied := os.NewSyscallError("bind", windows.WSAEACCES)
	// script returns the given errors in order, then success.
	script := func(calls *int, errs ...error) func() (*udpSocket, error) {
		return func() (*udpSocket, error) {
			*calls++
			if *calls <= len(errs) {
				return nil, errs[*calls-1]
			}
			return &udpSocket{}, nil
		}
	}
	for _, tc := range []struct {
		name                string
		errs                []error
		calls               int
		first, fresh, final uint64
		recovered           []uint64
		wantErr             error
	}{
		{"first attempt", nil, 1, 0, 0, 0, []uint64{0, 0, 0, 0}, nil},
		{"other error is not retried", []error{denied}, 1, 0, 0, 0, []uint64{0, 0, 0, 0}, windows.WSAEACCES},
		{"second fresh attempt", []error{refused, refused}, 3, 1, 2, 0, []uint64{0, 1, 0, 0}, nil},
		{"every attempt refused", []error{refused, refused, refused, refused, refused}, 5, 1, 4, 1, []uint64{0, 0, 0, 0}, windows.WSAENOBUFS},
		{"other error after a refusal ends it", []error{refused, denied}, 2, 1, 1, 1, []uint64{0, 0, 0, 0}, windows.WSAEACCES},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var r udpBindRetries
			calls := 0
			s, err := r.open(script(&calls, tc.errs...))
			if tc.wantErr == nil && (err != nil || s == nil) || tc.wantErr != nil && (!errors.Is(err, tc.wantErr) || s != nil) {
				t.Fatalf("open = %v, %v; want error %v", s, err, tc.wantErr)
			}
			stats := r.stats()
			if calls != tc.calls || stats["firstRefusals"] != tc.first || stats["freshAttempts"] != tc.fresh || stats["finalFailures"] != tc.final {
				t.Fatalf("calls %d stats %v", calls, stats)
			}
			for i, want := range tc.recovered {
				if got := stats["recoveredOnFreshAttempt"].([]uint64)[i]; got != want {
					t.Fatalf("recovered on fresh attempt %d = %d, want %d", i+1, got, want)
				}
			}
		})
	}
	t.Run("time window", func(t *testing.T) {
		var r udpBindRetries
		calls := 0
		_, err := r.open(func() (*udpSocket, error) {
			calls++
			if calls > 1 {
				time.Sleep(udpFreshWindow)
			}
			return nil, refused
		})
		stats := r.stats()
		if !errors.Is(err, windows.WSAENOBUFS) || calls != 2 || stats["windowEnded"] != uint64(1) || stats["finalFailures"] != uint64(1) {
			t.Fatalf("calls %d err %v stats %v", calls, err, stats)
		}
	})
}
