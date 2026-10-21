//go:build windows

package wintun

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/winclock"
	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

// inProcessOwner is the former engine-held registration. It exists only in
// test files: as the matched in-process baseline for comparisons, and as the
// negative control for its removal close race. Production code cannot reach
// it, so it can never become a silent fallback.
type inProcessOwner struct {
	device      windows.Handle
	deviceOwner winhandle.Owner
	registered  bool
}

func (*inProcessOwner) exited() windows.Handle { return 0 }

func openInProcessRings(path string, capacity uint32) (_ *rings, err error) {
	r, err := allocateRings(capacity)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, r.close())
		}
	}()
	if err = r.createEvents(); err != nil {
		return nil, err
	}
	o := &inProcessOwner{}
	r.owner = o
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	o.device, err = windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		o.device = 0
		return nil, err
	}
	o.deviceOwner = winhandle.OpenDriverHandle(o.device, "in-process Wintun ring device open")
	desc := registration{
		Send:    ringRegistration{uint32(len(r.send.bytes)), &r.send.bytes[0], r.readHandle()},
		Receive: ringRegistration{uint32(len(r.receive.bytes)), &r.receive.bytes[0], r.writeHandle()},
	}
	var returned uint32
	err = windows.DeviceIoControl(o.deviceOwner.Handle("in-process Wintun ring registration"), registerRingsIOCTL, (*byte)(unsafe.Pointer(&desc)), uint32(unsafe.Sizeof(desc)), nil, 0, &returned, nil)
	if err != nil {
		return nil, fmt.Errorf("register Wintun rings: %w", err)
	}
	o.registered = true
	return r, nil
}

func (a *Adapter) startInProcessSession() (*Session, error) {
	return a.startSession(func() (*rings, error) { return openInProcessRings(a.devicePath, a.config.Capacity) })
}

// end is the former production close, unchanged in its ordering: it checks
// the markers, then closes the device value. That order is the race the
// registrar removes. The driver locked this process's view, so an unreleased
// registration retains it.
func (o *inProcessOwner) end(r *rings, closeHandle func(windows.Handle) error) (bool, error) {
	var err error
	h := o.device
	o.device = 0
	closedDevice := false
	released := !o.registered || r.send.load(4) == ^uint32(0)
	if o.registered && !released && r.receive.load(0) == ^uint32(0) {
		started := winclock.Now()
		released = r.awaitRelease()
		r.closeProfile.DriverWaitNanos += uint64(winclock.Since(started))
	} else if h != 0 && (!o.registered || !released) {
		started := winclock.Now()
		closedDevice = true
		if o.deviceOwner.IsZero() {
			err = closeHandle(h) // Injected synthetic close, not a native open.
		} else {
			err = o.deviceOwner.Close("in-process Wintun ring device close", closeHandle)
		}
		r.closeProfile.DeviceNanos = uint64(winclock.Since(started))
		if o.registered {
			started = winclock.Now()
			released = r.awaitRelease()
			r.closeProfile.DriverWaitNanos += uint64(winclock.Since(started))
			if released && errors.Is(err, windows.ERROR_INVALID_HANDLE) {
				err = nil
			}
		}
	}
	if !closedDevice && !o.deviceOwner.IsZero() {
		o.deviceOwner.DriverReleased("in-process Wintun driver removal observed")
	}
	return !released, err
}
