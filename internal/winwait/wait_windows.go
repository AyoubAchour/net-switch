//go:build windows

// Package winwait waits on a Windows handle array without the stack-move
// hazard in x/sys's wrapper.
//
// windows.WaitForMultipleObjects converts &handles[0] to a uintptr and then
// calls an unannotated helper, which runs the lazy procedure lookup before
// syscall.SyscallN. A uintptr is not a pointer to the runtime: if either of
// those calls grows the goroutine's stack (or the stack is shrunk while the
// goroutine is preempted there), a caller's stack-allocated array moves and
// the kernel reads whatever now occupies the old address. The caller sees
// "The handle is invalid." or a wait on unrelated objects.
//
// Here the procedure is resolved first and the pointer is converted only
// inside the SyscallN argument list. SyscallN is //go:uintptrkeepalive and
// //go:nosplit, so nothing between the conversion and the kernel call can
// move the array. WaitForMultipleObjects is synchronous: the kernel does not
// keep the array after the call returns.
//
// This is a local copy of the shared helper #50 adds in internal/platform;
// callers switch to it once that lands, with the same signature.
package winwait

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// maximumWaitObjects is MAXIMUM_WAIT_OBJECTS from winnt.h.
const maximumWaitObjects = 64

var procWaitForMultipleObjects = windows.NewLazySystemDLL("kernel32.dll").NewProc("WaitForMultipleObjects")

// WaitForMultipleObjects waits like the Win32 function and returns its
// result (WAIT_OBJECT_0+i, WAIT_ABANDONED_0+i or WAIT_TIMEOUT).
func WaitForMultipleObjects(handles []windows.Handle, waitAll bool, milliseconds uint32) (uint32, error) {
	if len(handles) == 0 || len(handles) > maximumWaitObjects {
		return windows.WAIT_FAILED, syscall.EINVAL
	}
	if err := procWaitForMultipleObjects.Find(); err != nil {
		return windows.WAIT_FAILED, err
	}
	addr := procWaitForMultipleObjects.Addr()
	all := uintptr(0)
	if waitAll {
		all = 1
	}
	r, _, e := syscall.SyscallN(addr, uintptr(len(handles)), uintptr(unsafe.Pointer(&handles[0])), all, uintptr(milliseconds))
	if uint32(r) == windows.WAIT_FAILED {
		if e == 0 {
			return windows.WAIT_FAILED, syscall.EINVAL
		}
		return windows.WAIT_FAILED, e
	}
	return uint32(r), nil
}
