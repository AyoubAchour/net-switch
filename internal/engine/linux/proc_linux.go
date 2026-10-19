//go:build linux

package linux

import (
	"errors"

	"golang.org/x/sys/unix"
)

// procfs and cgroupfs generate these small files synchronously. Registering
// each one with Go's network poller adds fcntl/epoll calls that the kernel then
// rejects. Use ordinary bounded reads, retaining EINTR handling and a hard
// allocation ceiling. Only kernel-owned paths use this helper.
func readKernelFile(path string, limit int) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	b := make([]byte, min(512, limit))
	n := 0
	for {
		if n == len(b) {
			if n == limit {
				var extra [1]byte
				got, err := unix.Read(fd, extra[:])
				if errors.Is(err, unix.EINTR) {
					continue
				}
				if err != nil {
					return nil, err
				}
				if got == 0 {
					return b[:n], nil
				}
				return nil, errors.New("kernel file exceeds read limit")
			}
			b = append(b, make([]byte, min(len(b), limit-len(b)))...)
		}
		got, err := unix.Read(fd, b[n:])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if got == 0 {
			return b[:n], nil
		}
		n += got
	}
}
