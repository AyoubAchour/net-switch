//go:build windows

// Package winapi wraps the few Windows calls whose x/sys wrappers hand the
// kernel an address the Go runtime does not protect.
//
// x/sys's WaitForMultipleObjects, SetInformationJobObject and
// QueryInformationJobObject turn the caller's handle array or information
// block into a uintptr and only then make further Go calls (an unannotated
// helper, the procedure lookup) before the syscall. A uintptr is just a
// number: the object can be collected, and a stack-allocated one moves when
// those calls grow the stack, so the kernel reads stale memory. Escape
// analysis leaves small handle literals and job limits on the stack.
//
// Here the procedure address is resolved first, and the Go pointer is
// converted only inside the syscall.SyscallN argument list. The compiler
// keeps it a pointer until the call (//go:uintptrkeepalive) and SyscallN
// does not grow the stack (//go:nosplit), so the object stays alive and in
// place while the kernel uses it. These calls are synchronous.
package winapi

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32         = windows.NewLazySystemDLL("kernel32.dll")
	procWaitMultiple = kernel32.NewProc("WaitForMultipleObjects")
	procSetJob       = kernel32.NewProc("SetInformationJobObject")
	procQueryJob     = kernel32.NewProc("QueryInformationJobObject")
)

// WaitForMultipleObjects waits on handles like the Win32 function. It
// returns the wait result (WAIT_OBJECT_0+i, WAIT_ABANDONED_0+i or
// WAIT_TIMEOUT).
func WaitForMultipleObjects(handles []windows.Handle, waitAll bool, milliseconds uint32) (uint32, error) {
	if len(handles) == 0 {
		return 0, syscall.EINVAL
	}
	addr, err := address(procWaitMultiple)
	if err != nil {
		return 0, err
	}
	all := uintptr(0)
	if waitAll {
		all = 1
	}
	r, _, e := syscall.SyscallN(addr, uintptr(len(handles)), uintptr(unsafe.Pointer(&handles[0])), all, uintptr(milliseconds))
	if uint32(r) == windows.WAIT_FAILED {
		return uint32(r), errno(e)
	}
	return uint32(r), nil
}

// SetJobInformation calls SetInformationJobObject with info as the block.
func SetJobInformation[T any](job windows.Handle, class uint32, info *T) error {
	addr, err := address(procSetJob)
	if err != nil {
		return err
	}
	r, _, e := syscall.SyscallN(addr, uintptr(job), uintptr(class), uintptr(unsafe.Pointer(info)), unsafe.Sizeof(*info))
	if r == 0 {
		return errno(e)
	}
	return nil
}

// QueryJobInformation calls QueryInformationJobObject, filling info.
func QueryJobInformation[T any](job windows.Handle, class uint32, info *T) error {
	addr, err := address(procQueryJob)
	if err != nil {
		return err
	}
	r, _, e := syscall.SyscallN(addr, uintptr(job), uintptr(class), uintptr(unsafe.Pointer(info)), unsafe.Sizeof(*info), 0)
	if r == 0 {
		return errno(e)
	}
	return nil
}

func address(p *windows.LazyProc) (uintptr, error) {
	if err := p.Find(); err != nil {
		return 0, err
	}
	return p.Addr(), nil
}

func errno(e syscall.Errno) error {
	if e == 0 {
		return syscall.EINVAL
	}
	return e
}
