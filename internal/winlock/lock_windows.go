//go:build windows

// Package winlock serializes Windows ownership through a caller-verified file.
package winlock

import (
	"context"
	"errors"
	"time"

	"golang.org/x/sys/windows"
)

// Acquire locks byte zero exclusively. The caller opens a synchronous,
// read/write file in a verified private directory and owns its handle.
// Closing the handle releases the lock, including on process termination.
// File/path/ACL validation belongs to the caller; this helper does not open,
// create, truncate, rename or delete anything.
func Acquire(ctx context.Context, handle windows.Handle) error {
	var operation windows.Overlapped
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &operation)
		if err == nil || !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return err
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
