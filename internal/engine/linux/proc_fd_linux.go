//go:build linux

package linux

import (
	"bytes"
	"encoding/binary"
	"io"

	"golang.org/x/sys/unix"
)

// procDescriptors is a single scanner's pinned /proc/PID/fd directory. Seek
// discards unread records but retains scratch storage. Names are borrowed only
// during Visit's callback; a positive socket hint copies the name it retains.
type procDescriptors struct {
	fd            int
	open          bool
	direct        bool
	buffer        *[16 << 10]byte
	position, end int
	trace         *descriptorTrace
}

func openProcDescriptors(path string) (procDescriptors, error) {
	fd, direct, err := openKernelFile(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW)
	if err != nil {
		return procDescriptors{}, err
	}
	return procDescriptors{fd: fd, open: true, direct: direct}, nil
}

func (d *procDescriptors) Close() error {
	if !d.open {
		return nil
	}
	d.open = false
	if d.buffer != nil {
		processBuffers.Put(d.buffer)
		d.buffer = nil
	}
	return closeKernelFile(d.fd, d.direct)
}

func (d *procDescriptors) Seek(offset int64, whence int) (int64, error) {
	if !d.open {
		return 0, unix.EBADF
	}
	d.position, d.end = 0, 0
	return seekKernelDirectory(d.fd, d.direct, offset, whence)
}

func (d *procDescriptors) Visit(limit int, consume func([]byte) bool) (int, error) {
	if !d.open {
		return 0, unix.EBADF
	}
	if d.buffer == nil && limit > 0 {
		read := -1
		if d.trace != nil {
			read = d.trace.begin(-2)
		}
		d.buffer = processBuffers.Get()
		if d.trace != nil {
			d.trace.end(read)
		}
	}
	count := 0
	for count < limit {
		if d.position == d.end {
			// Numeric fd records occupy at most 32 bytes. A small targeted
			// window must not make procfs instantiate hundreds of additional
			// entries that the following seek would immediately discard.
			size := min(len(d.buffer), (min(limit-count, 512)+2)*32)
			// procfs temporarily references each target file. Dropping its
			// last reference can invoke a blocking close, including SO_LINGER.
			read := -1
			if d.trace != nil {
				read = d.trace.begin(-1)
			}
			n, err := unix.ReadDirent(d.fd, d.buffer[:size])
			if d.trace != nil {
				d.trace.end(read)
			}
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				return count, err
			}
			if n == 0 {
				return count, io.EOF
			}
			d.position, d.end = 0, n
		}
		// Linux getdents64: inode(8), next-position(8), length(2),
		// type(1), then a NUL-terminated name. Do not filter by inode or
		// d_type: neither is needed to validate a numeric descriptor link.
		record := d.buffer[d.position:d.end]
		if len(record) < 20 {
			return count, unix.EIO
		}
		length := int(binary.NativeEndian.Uint16(record[16:18]))
		if length < 20 || length > len(record) {
			return count, unix.EIO
		}
		name := record[19:length]
		terminator := bytes.IndexByte(name, 0)
		if terminator < 0 {
			return count, unix.EIO
		}
		name = name[:terminator]
		d.position += length
		if bytes.Equal(name, []byte(".")) || bytes.Equal(name, []byte("..")) {
			continue
		}
		count++
		if !consume(name) {
			return count, nil
		}
	}
	return count, nil
}
