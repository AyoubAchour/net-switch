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

// Only fixed kernel metadata in the engine's own proc/cgroup mounts is marked
// direct: its stat, seek and close keep the lookup's Go processor across short
// operations. Every open, including these, is a scheduling syscall. Opening
// allocates a descriptor before resolving the path, and that allocation can
// grow the shared descriptor table (an RCU grace period, or waiting for a
// concurrent resize) or wait for memory reclaim. Never extend direct to
// /proc/PID/root or other process-controlled filesystems. Environ opens wait
// on the target's exec_update_lock, and its contents can fault in user
// memory, so it is never direct.
func openKernelFile(path string, flags int) (fd int, direct bool, err error) {
	fd, err = unix.Open(path, flags, 0)
	if err != nil {
		return -1, false, err
	}
	return fd, kernelLookupPath(path), nil
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
