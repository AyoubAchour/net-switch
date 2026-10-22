//go:build windows

package winengine

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestOwnershipPreparationWait(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result uint32
		err    error
		want   error
	}{
		{"available", windows.WAIT_OBJECT_0, nil, nil},
		{"crashed-initializer", windows.WAIT_ABANDONED, nil, nil},
		{"native-failure", windows.WAIT_FAILED, windows.ERROR_INVALID_HANDLE, windows.ERROR_INVALID_HANDLE},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := waitOwnershipPreparation(context.Background(), func() (uint32, error) { return tc.result, tc.err })
			if !errors.Is(err, tc.want) {
				t.Fatalf("wait result: %v, want %v", err, tc.want)
			}
		})
	}
	t.Run("unexpected-result", func(t *testing.T) {
		if err := waitOwnershipPreparation(context.Background(), func() (uint32, error) { return 123, nil }); err == nil {
			t.Fatal("unexpected wait result granted preparation")
		}
	})
	t.Run("canceled-before-wait", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := waitOwnershipPreparation(ctx, func() (uint32, error) {
			t.Fatal("canceled caller attempted to acquire")
			return 0, nil
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
	t.Run("canceled-while-contended", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		calls := 0
		err := waitOwnershipPreparation(ctx, func() (uint32, error) {
			calls++
			return uint32(windows.WAIT_TIMEOUT), nil
		})
		if calls == 0 || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("contended wait: calls=%d err=%v", calls, err)
		}
	})
	t.Run("canceled-local-contender", func(t *testing.T) {
		ownershipPreparationGate <- struct{}{}
		defer func() { <-ownershipPreparationGate }()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		err := withOwnershipPreparation(ctx, func() error {
			t.Fatal("local contender bypassed the preparation gate")
			return nil
		})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	})
}
