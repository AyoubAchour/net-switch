//go:build linux

package linux

import (
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func decimalName(s string) bool {
	if s == "" {
		return false
	}
	for i := range s {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func procLeaf(path string) string {
	rest, ok := strings.CutPrefix(path, "/proc/")
	if !ok {
		return ""
	}
	pid, leaf, ok := strings.Cut(rest, "/")
	if !ok || (pid != "self" && !decimalName(pid)) {
		return ""
	}
	return leaf
}

func kernelScopePath(path string) bool {
	return strings.HasPrefix(path, "/sys/fs/cgroup/") && strings.HasSuffix(path, "/cgroup.procs") && !strings.Contains(path, "/./") && !strings.Contains(path, "/../")
}

func kernelLookupPath(path string) bool {
	switch procLeaf(path) {
	case "stat", "fd":
		return true
	}
	return kernelScopePath(path)
}

// Only fixed kernel metadata in the engine's own proc/cgroup mounts uses
// these calls. They keep the lookup's Go processor across short operations.
// Never extend this to /proc/PID/root or other process-controlled filesystems.
// Environ opens wait on the target's exec_update_lock, and its contents can
// fault in user memory. Both its opens and reads remain scheduling syscalls.
func openKernelFile(path string, flags int) (fd int, direct bool, err error) {
	if !kernelLookupPath(path) {
		fd, err = unix.Open(path, flags, 0)
		return fd, false, err
	}
	name, err := unix.BytePtrFromString(path)
	if err != nil {
		return -1, false, err
	}
	dir := unix.AT_FDCWD
	value, _, errno := syscall.RawSyscall6(unix.SYS_OPENAT, uintptr(dir), uintptr(unsafe.Pointer(name)), uintptr(flags), 0, 0, 0)
	if errno != 0 {
		return -1, false, errno
	}
	return int(value), true, nil
}

func closeKernelFile(fd int, direct bool) error {
	if !direct {
		return unix.Close(fd)
	}
	_, _, errno := syscall.RawSyscall(unix.SYS_CLOSE, uintptr(fd), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func statKernelFile(fd int, direct bool, stat *unix.Stat_t) error {
	if !direct {
		return unix.Fstat(fd, stat)
	}
	return rawKernelStat(fd, stat)
}

func readKernelData(fd int, b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	n, _, errno := syscall.RawSyscall(unix.SYS_READ, uintptr(fd), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}

func readKernelLink(path string, b []byte) (int, error) {
	leaf := procLeaf(path)
	fd, descriptor := strings.CutPrefix(leaf, "fd/")
	if len(path) >= 64 || (leaf != "exe" && !(descriptor && decimalName(fd))) {
		return unix.Readlink(path, b)
	}
	if len(b) == 0 {
		return 0, unix.EINVAL
	}
	var name [64]byte
	copy(name[:], path)
	dir := unix.AT_FDCWD
	// Keep stack-backed path storage, but release the Go processor. procfs
	// drops a temporary file reference before returning; a concurrent target
	// close can make it the last reference and run socket linger here.
	n, _, errno := syscall.Syscall6(unix.SYS_READLINKAT, uintptr(dir), uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}
