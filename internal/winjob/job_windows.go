//go:build windows

// Package winjob sets and reads job object information without handing the
// kernel an unprotected address.
//
// x/sys's SetInformationJobObject and QueryInformationJobObject take the
// information block as a plain uintptr. A caller's uintptr(unsafe.Pointer(&v))
// is then only a number: nothing keeps v alive, and if the wrapper's call
// chain grows the stack, a stack-allocated v moves while the kernel is given
// its old address. Here the block stays a Go pointer until the conversion
// inside the syscall.SyscallN argument list, which the compiler keeps alive
// for the call, and SyscallN does not grow the stack.
package winjob

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32  = windows.NewLazySystemDLL("kernel32.dll")
	procSet   = kernel32.NewProc("SetInformationJobObject")
	procQuery = kernel32.NewProc("QueryInformationJobObject")
)

// Set calls SetInformationJobObject with info as the information block.
func Set[T any](job windows.Handle, class uint32, info *T) error {
	return set(job, class, unsafe.Pointer(info), uint32(unsafe.Sizeof(*info)))
}

// Query calls QueryInformationJobObject, filling info.
func Query[T any](job windows.Handle, class uint32, info *T) error {
	return query(job, class, unsafe.Pointer(info), uint32(unsafe.Sizeof(*info)))
}

func set(job windows.Handle, class uint32, info unsafe.Pointer, size uint32) error {
	if err := procSet.Find(); err != nil {
		return err
	}
	r, _, err := syscall.SyscallN(procSet.Addr(), uintptr(job), uintptr(class), uintptr(info), uintptr(size))
	return result(r, err)
}

func query(job windows.Handle, class uint32, info unsafe.Pointer, size uint32) error {
	if err := procQuery.Find(); err != nil {
		return err
	}
	r, _, err := syscall.SyscallN(procQuery.Addr(), uintptr(job), uintptr(class), uintptr(info), uintptr(size), 0)
	return result(r, err)
}

func result(r uintptr, err syscall.Errno) error {
	if r != 0 {
		return nil
	}
	if err == 0 {
		return syscall.EINVAL
	}
	return err
}
