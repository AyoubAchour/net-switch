//go:build !windows

package protocol

import "time"

// On Linux Go uses CLOCK_MONOTONIC, which stops during suspend.
func leaseNow() time.Time { return time.Now() }
