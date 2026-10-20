package protocol

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var unbiasedInterruptTime = windows.NewLazySystemDLL("api-ms-win-core-realtime-l1-1-1.dll").NewProc("QueryUnbiasedInterruptTimePrecise")

// Unlike Go's Windows monotonic clock, this excludes sleep and hibernation.
// Windows 10 22H2 (our minimum) includes the precise API.
func leaseNow() time.Time {
	var ticks uint64
	unbiasedInterruptTime.Call(uintptr(unsafe.Pointer(&ticks)))
	return time.Unix(0, int64(ticks)*100)
}
