package service

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func publishPowerEvent(events *EventQueue, kind uint32) {
	switch kind {
	case 4: // PBT_APMSUSPEND
		events.Publish(Event{Suspend: true})
	case 7, 18: // PBT_APMRESUMESUSPEND, PBT_APMRESUMEAUTOMATIC
		events.Publish(Event{Resume: true})
	}
}

// powerSubscription is DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS. Windows does not
// document whether it copies the structure, so it stays on the heap and
// referenced until the registration is removed.
type powerSubscription struct{ Callback, Context uintptr }

// The callback subscription also receives Modern Standby transitions; SCM
// PowerEvent delivery alone is insufficient. No callback-owned buffer escapes.
func registerPowerEvents(events *EventQueue) (func(), error) {
	dll := windows.NewLazySystemDLL("powrprof.dll")
	parameters := &powerSubscription{
		Callback: windows.NewCallback(func(_ uintptr, kind uint32, _ uintptr) uintptr {
			publishPowerEvent(events, kind)
			return 0
		}),
	}
	var handle windows.Handle
	code, _, _ := dll.NewProc("PowerRegisterSuspendResumeNotification").Call(2, uintptr(unsafe.Pointer(parameters)), uintptr(unsafe.Pointer(&handle)))
	if code != 0 {
		return nil, windows.Errno(code)
	}
	return func() {
		dll.NewProc("PowerUnregisterSuspendResumeNotification").Call(uintptr(handle))
		runtime.KeepAlive(parameters)
	}, nil
}
