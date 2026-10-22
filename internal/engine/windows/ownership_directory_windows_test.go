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

// Review of 822789db: CreatePrivateNamespaceW can report the namespace exists
// and the other process can close its last handle before OpenPrivateNamespaceW,
// which then fails. Startup creates again instead of failing; the sequences
// are injected.
func TestOwnershipNamespaceCreateOrOpenRace(t *testing.T) {
	exists, gone := windows.ERROR_ALREADY_EXISTS, windows.ERROR_PATH_NOT_FOUND
	type step struct {
		h   uintptr
		err error
	}
	for _, tc := range []struct {
		name                   string
		creates                []step
		opens                  []step
		cancel                 bool
		want                   uintptr
		wantErr                error
		wantCreates, wantOpens int
	}{
		{"created", []step{{7, nil}}, nil, false, 7, nil, 1, 0},
		{"opened", []step{{0, exists}}, []step{{8, nil}}, false, 8, nil, 1, 1},
		{"gone before the open, created again", []step{{0, exists}, {9, nil}}, []step{{0, gone}}, false, 9, nil, 2, 1},
		{"gone twice, then opened", []step{{0, exists}, {0, exists}, {0, exists}}, []step{{0, gone}, {0, windows.ERROR_FILE_NOT_FOUND}, {10, nil}}, false, 10, nil, 3, 3},
		{"gone every round", nil, nil, false, 0, gone, namespaceAttempts, namespaceAttempts},
		{"open denied is not retried", []step{{0, exists}}, []step{{0, windows.ERROR_ACCESS_DENIED}}, false, 0, windows.ERROR_ACCESS_DENIED, 1, 1},
		{"create denied is not retried", []step{{0, windows.ERROR_ACCESS_DENIED}}, nil, false, 0, windows.ERROR_ACCESS_DENIED, 1, 0},
		{"cancelled", nil, nil, true, 0, context.Canceled, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			created, opened := 0, 0
			next := func(steps []step, n int, fallback step) (uintptr, error) {
				if n <= len(steps) {
					return steps[n-1].h, steps[n-1].err
				}
				return fallback.h, fallback.err
			}
			h, err := createOrOpenNamespace(ctx,
				func() (uintptr, error) { created++; return next(tc.creates, created, step{0, exists}) },
				func() (uintptr, error) { opened++; return next(tc.opens, opened, step{0, gone}) })
			if h != tc.want || (tc.wantErr == nil) != (err == nil) || (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) ||
				created != tc.wantCreates || opened != tc.wantOpens {
				t.Fatalf("handle %d err %v after %d creates and %d opens", h, err, created, opened)
			}
		})
	}
}
