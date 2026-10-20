package service

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func publishPowerEvent(events chan Event, kind uint32) {
	var event Event
	switch kind {
	case 4: // PBT_APMSUSPEND
		event.Suspend = true
	case 7, 18: // PBT_APMRESUMESUSPEND, PBT_APMRESUMEAUTOMATIC
		event.Resume = true
	default:
		return
	}
	select {
	case events <- event:
	default:
	}
}

// The callback subscription also receives Modern Standby transitions; SCM
// PowerEvent delivery alone is insufficient. No callback-owned buffer escapes.
func registerPowerEvents(events chan Event) (func(), error) {
	dll := windows.NewLazySystemDLL("powrprof.dll")
	parameters := struct{ Callback, Context uintptr }{
		Callback: windows.NewCallback(func(_ uintptr, kind uint32, _ uintptr) uintptr {
			publishPowerEvent(events, kind)
			return 0
		}),
	}
	var handle windows.Handle
	code, _, _ := dll.NewProc("PowerRegisterSuspendResumeNotification").Call(2, uintptr(unsafe.Pointer(&parameters)), uintptr(unsafe.Pointer(&handle)))
	if code != 0 {
		return nil, windows.Errno(code)
	}
	return func() {
		dll.NewProc("PowerUnregisterSuspendResumeNotification").Call(uintptr(handle))
		runtime.KeepAlive(parameters)
	}, nil
}
