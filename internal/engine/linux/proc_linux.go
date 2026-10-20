//go:build linux

package linux

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

var errKernelFileLimit = errors.New("kernel file exceeds read limit")
var errNotRegular = errors.New("identity metadata is not a regular file")
var processBuffers = sync.Pool{New: func() any { return new([16 << 10]byte) }}
var flatpakBuffers = sync.Pool{New: func() any { return new([64 << 10]byte) }}
var rejectedMetadata atomic.Uint64
var lastRejectedMetadata atomic.Pointer[string]

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
		Flags:   unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	// O_RDONLY would invoke a bind-mounted device's open handler before
	// fstat could reject it. O_PATH pins the inode without opening the device.
	if err := regularFile(fd, -1); err != nil {
		return nil, err
	}
	// This sole intentional magic-link reopen belongs to this engine, not
	// the target process. fd remains open, so rename/mount races cannot swap
	// its inode. NONBLOCK applies here; NOFOLLOW would reject our own fd link.
	readFD, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", fd), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(readFD)
	data, err := readBounded(readFD, b)
	if errors.Is(err, errKernelFileLimit) {
		// Flatpak serializes environment overrides and arguments after its
		// identity. A complete name line within the bound is sufficient;
		// never interpret a line cut off at the cap as an application ID.
		section, offset := false, 0
		for offset < len(data) {
			end := bytes.IndexByte(data[offset:], '\n')
			if end < 0 {
				break
			}
			line := bytes.TrimSpace(data[offset : offset+end])
			offset += end + 1
			if bytes.HasPrefix(line, []byte("[")) {
				section = bytes.Equal(line, []byte("[Application]"))
			}
			if section && bytes.HasPrefix(line, []byte("name=")) && len(line) > 5 {
				return data[:offset], nil
			}
		}
		return nil, err
	}
	return data, err
}

func regularFile(fd int, limit int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return errNotRegular
	}
	if limit >= 0 && st.Size > int64(limit) {
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
	return readBounded(fd, b)
}

func readBounded(fd int, b []byte) ([]byte, error) {
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
		return b[:n], errKernelFileLimit
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

// Descriptor links need only the kernel's short socket:[inode] form. Reading
// relative to an already opened fd directory avoids resolving /proc/PID/fd
// again for every descriptor in a shared scan. Long ordinary-file links are
// deliberately ignored; they can never be socket identities.
func socketInodeAt(dir int, name string) (uint32, bool) {
	var b [64]byte
	n, err := unix.Readlinkat(dir, name, b[:])
	if err != nil || n >= len(b) || n < 10 || !bytes.HasPrefix(b[:n], []byte("socket:[")) || b[n-1] != ']' {
		return 0, false
	}
	inode, err := strconv.ParseUint(string(b[8:n-1]), 10, 32)
	return uint32(inode), err == nil
}
