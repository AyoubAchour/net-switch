//go:build !windows

package stack_test

import (
	"testing"
	"time"
)

func newLatencyClock(_ testing.TB) func() time.Duration {
	origin := time.Now()
	return func() time.Duration { return time.Since(origin) }
}
