//go:build linux && !amd64 && !arm64

package linux

import "golang.org/x/sys/unix"

// Other ABIs keep x/sys's stat layout and 64-bit seek compatibility handling.
func rawKernelStat(fd int, stat *unix.Stat_t) error { return unix.Fstat(fd, stat) }
func seekKernelDirectory(fd int, _ bool, offset int64, whence int) (int64, error) {
	return unix.Seek(fd, offset, whence)
}
