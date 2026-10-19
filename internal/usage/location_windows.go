package usage

import (
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// The Windows key is language independent; StandardName is localized.
// https://learn.microsoft.com/windows/win32/api/timezoneapi/nf-timezoneapi-getdynamictimezoneinformation
type dynamicZone struct {
	Bias         int32
	StandardName [32]uint16
	StandardDate syscall.Systemtime
	StandardBias int32
	DaylightName [32]uint16
	DaylightDate syscall.Systemtime
	DaylightBias int32
	Key          [128]uint16
	Disabled     byte
}

var getDynamicZone = syscall.NewLazyDLL("kernel32.dll").NewProc("GetDynamicTimeZoneInformation")

// LocalLocation loads full IANA history from bundled tzdata, not time.Local's
// current-year approximation. TZ is an explicit IANA override for tests/control.
// Resolve once when constructing Usage; failures must be reported at startup.
func LocalLocation() (*time.Location, error) {
	if name := os.Getenv("TZ"); name != "" {
		if name == "Local" {
			return nil, fmt.Errorf("TZ must name an IANA zone, not Local")
		}
		return time.LoadLocation(name)
	}
	var info dynamicZone
	result, _, err := getDynamicZone.Call(uintptr(unsafe.Pointer(&info)))
	if uint32(result) == 0xffffffff {
		return nil, fmt.Errorf("read Windows time zone: %w", err)
	}
	key := syscall.UTF16ToString(info.Key[:])
	name, ok := windowsZones[key]
	if !ok {
		return nil, fmt.Errorf("no IANA mapping for Windows time zone %q; set TZ to its IANA name", key)
	}
	return time.LoadLocation(name)
}
