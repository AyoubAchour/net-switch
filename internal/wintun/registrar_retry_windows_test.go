//go:build windows

package wintun

import (
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestRegistrarBusyRetryOnlyUnclaimedRegistration(t *testing.T) {
	for _, succeeds := range []bool{true, false} {
		calls := 0
		var waited time.Duration
		err := registerWithBusyRetry(func() error {
			calls++
			if succeeds && calls == 7 {
				return nil
			}
			return windows.ERROR_ALREADY_INITIALIZED
		}, func(d time.Duration) { waited += d })
		if calls != 7 || waited != 630*time.Millisecond || (err == nil) != succeeds {
			t.Fatal(calls, waited, err)
		}
	}
	calls := 0
	err := registerWithBusyRetry(func() error { calls++; return windows.ERROR_ACCESS_DENIED }, func(time.Duration) { t.Fatal("retried permanent error") })
	if calls != 1 || err != windows.ERROR_ACCESS_DENIED {
		t.Fatal(calls, err)
	}
}
