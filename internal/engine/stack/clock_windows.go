//go:build windows

package stack

import (
	"time"

	"github.com/AyoubAchour/net-switch/internal/winclock"
	"gvisor.dev/gvisor/pkg/tcpip"
)

type windowsClock struct{ origin time.Duration }

func nativeClock() (tcpip.Clock, time.Duration) {
	return windowsClock{origin: winclock.Now()}, 500 * time.Microsecond
}

func (windowsClock) Now() time.Time { return time.Now() }
func (c windowsClock) NowMonotonic() tcpip.MonotonicTime {
	return tcpip.MonotonicTime{}.Add(winclock.Since(c.origin))
}
func (windowsClock) AfterFunc(d time.Duration, f func()) tcpip.Timer {
	return winclock.System.AfterFunc(d, f)
}
