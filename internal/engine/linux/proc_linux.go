//go:build linux

package linux

import (
	"errors"
	"sync"

	"golang.org/x/sys/unix"
)

var errKernelFileLimit = errors.New("kernel file exceeds read limit")
var errNotRegular = errors.New("identity metadata is not a regular file")
var processBuffers = sync.Pool{New: func() any { return new([16 << 10]byte) }}
var flatpakBuffers = sync.Pool{New: func() any { return new([64 << 10]byte) }}

// The process root is deliberately followed once. Nothing below that pinned
// directory may resolve a symlink, including a procfs magic link. Flatpak bind
// mounts its regular metadata file here, so crossing a mount is legitimate.
func readFlatpakInfo(root string, b []byte) ([]byte, error) {
	dir, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	fd, err := unix.Openat2(dir, ".flatpak-info", &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	return readRegularInto(fd, b)
}

func regularFile(fd int, limit int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return errNotRegular
	}
	if st.Size > int64(limit) {
		return errKernelFileLimit
	}
	return nil
}

// Repeated identity checks borrow scratch space. No bytes from this buffer
// may escape the caller; only parsed numbers or copied identity strings do.
func readInto(path string, b []byte) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	return readRegularInto(fd, b)
}

func readRegularInto(fd int, b []byte) ([]byte, error) {
	if err := regularFile(fd, len(b)); err != nil {
		return nil, err
	}
	n := 0
	for n < len(b) {
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
	var extra [1]byte
	for {
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
		return nil, errKernelFileLimit
	}
}

// procfs and cgroupfs generate these small files synchronously. Registering
// each one with Go's network poller adds fcntl/epoll calls that the kernel then
// rejects. Use ordinary bounded reads, retaining EINTR handling and a hard
// allocation ceiling. Only kernel-owned paths use this helper.
func readKernelFile(path string, limit int) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if err := regularFile(fd, limit); err != nil {
		return nil, err
	}
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
				return nil, errKernelFileLimit
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

// exe and fd entries are read as link text, never opened. The kernel limits
// their targets to PATH_MAX; reject truncation instead of growing indefinitely.
func readProcLink(path string) (string, error) {
	var b [4096]byte
	n, err := unix.Readlink(path, b[:])
	if err != nil {
		return "", err
	}
	if n == len(b) {
		return "", errKernelFileLimit
	}
	return string(b[:n]), nil
}
