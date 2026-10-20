//go:build linux && (amd64 || arm64)

package linux

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func rawKernelStat(fd int, stat *unix.Stat_t) error {
	_, _, errno := syscall.RawSyscall(unix.SYS_FSTAT, uintptr(fd), uintptr(unsafe.Pointer(stat)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func seekKernelDirectory(fd int, direct bool, offset int64, whence int) (int64, error) {
	if !direct {
		return unix.Seek(fd, offset, whence)
	}
	position, _, errno := syscall.RawSyscall(unix.SYS_LSEEK, uintptr(fd), uintptr(offset), uintptr(whence))
	if errno != 0 {
		return 0, errno
	}
	return int64(position), nil
}
