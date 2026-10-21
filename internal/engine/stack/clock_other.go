//go:build !windows

package stack

import (
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

func nativeClock() (tcpip.Clock, time.Duration) { return nil, 0 }
