//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type socketRow struct {
	local, remote  netip.AddrPort
	uid, inode     uint32
	cookie, cgroup uint64
}

func (s socketRow) generation() string { return strconv.FormatUint(s.cookie, 16) }

func parseDiag(b []byte) (socketRow, error) {
	var r socketRow
	if len(b) < 72 {
		return r, errors.New("short inet_diag message")
	}
	var a, z netip.Addr
	switch b[0] {
	case unix.AF_INET:
		a = netip.AddrFrom4([4]byte(b[8:12]))
		z = netip.AddrFrom4([4]byte(b[24:28]))
	case unix.AF_INET6:
		a = netip.AddrFrom16([16]byte(b[8:24]))
		z = netip.AddrFrom16([16]byte(b[24:40]))
	default:
		return r, errors.New("unknown inet_diag family")
	}
	r.local = netip.AddrPortFrom(a, binary.BigEndian.Uint16(b[4:6]))
	r.remote = netip.AddrPortFrom(z, binary.BigEndian.Uint16(b[6:8]))
	r.cookie = uint64(binary.NativeEndian.Uint32(b[44:48])) | uint64(binary.NativeEndian.Uint32(b[48:52]))<<32
	r.uid = binary.NativeEndian.Uint32(b[64:68])
	r.inode = binary.NativeEndian.Uint32(b[68:72])
	for off := 72; off+4 <= len(b); {
		n := int(binary.NativeEndian.Uint16(b[off:]))
		kind := binary.NativeEndian.Uint16(b[off+2:]) & 0x3fff
		if n < 4 || off+n > len(b) {
			return r, errors.New("invalid inet_diag attribute")
		}
		if kind == 21 && n >= 12 {
			r.cgroup = binary.NativeEndian.Uint64(b[off+4:])
		}
		off += (n + 3) &^ 3
	}
	return r, nil
}

// Each query has its own descriptor: an interrupted/cancelled dump cannot
// leave replies that a subsequent lookup mistakes for its own response.
func diag(ctx context.Context, family, protocol int, local, remote netip.AddrPort, dump bool) ([]socketRow, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "sock_diag")
	defer f.Close()
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { f.SetReadDeadline(time.Now()) })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		f.SetReadDeadline(deadline)
	}
	b := make([]byte, 72)
	binary.NativeEndian.PutUint32(b, uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:], 20)
	flags := uint16(unix.NLM_F_REQUEST)
	if dump {
		flags |= unix.NLM_F_DUMP
	}
	binary.NativeEndian.PutUint16(b[6:], flags)
	binary.NativeEndian.PutUint32(b[8:], 1)
	b[16] = byte(family)
	b[17] = byte(protocol)
	binary.NativeEndian.PutUint32(b[20:], ^uint32(0))
	// UDP's exact query uses the inbound lookup convention (remote,local).
	if protocol == unix.IPPROTO_UDP && !dump {
		local, remote = remote, local
	}
	if local.IsValid() {
		binary.BigEndian.PutUint16(b[24:], local.Port())
		copy(b[28:44], local.Addr().AsSlice())
	}
	if remote.IsValid() {
		binary.BigEndian.PutUint16(b[26:], remote.Port())
		copy(b[44:60], remote.Addr().AsSlice())
	}
	for i := 64; i < 72; i++ {
		b[i] = 255
	}
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	buf := make([]byte, 256<<10)
	var rows []socketRow
	for {
		n, err := f.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
		messages, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, err
		}
		for _, m := range messages {
			if m.Header.Seq != 1 {
				return nil, errors.New("unexpected sock_diag sequence")
			}
			if m.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
				return nil, errDiagInterrupted
			}
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				if len(m.Data) >= 4 && binary.NativeEndian.Uint32(m.Data) != 0 {
					return nil, syscall.Errno(-int32(binary.NativeEndian.Uint32(m.Data)))
				}
				return rows, nil
			case unix.NLMSG_ERROR:
				if len(m.Data) < 4 {
					return nil, errors.New("short sock_diag error")
				}
				code := int32(binary.NativeEndian.Uint32(m.Data))
				if code != 0 {
					return nil, syscall.Errno(-code)
				}
			case 20:
				r, err := parseDiag(m.Data)
				if err != nil {
					return nil, err
				}
				rows = append(rows, r)
				if !dump {
					return rows, nil
				}
			case unix.NLMSG_OVERRUN:
				return nil, unix.ENOBUFS
			}
		}
	}
}

var errDiagInterrupted = errors.New("sock_diag dump interrupted")

func diagDump(ctx context.Context, family, protocol int, local netip.AddrPort) ([]socketRow, error) {
	for i := 0; i < 3; i++ {
		rows, err := diag(ctx, family, protocol, local, netip.AddrPort{}, true)
		if !errors.Is(err, errDiagInterrupted) {
			return rows, err
		}
	}
	return nil, errDiagInterrupted
}
func familyOf(a netip.Addr) int {
	if a.Is6() {
		return unix.AF_INET6
	}
	return unix.AF_INET
}
func matchUDP(rows []socketRow, source netip.AddrPort) (socketRow, error) {
	var exact, wild []socketRow
	for _, r := range rows {
		if r.local.Port() != source.Port() || r.local.Addr().BitLen() != source.Addr().BitLen() {
			continue
		}
		if r.local.Addr() == source.Addr() {
			exact = append(exact, r)
		} else if r.local.Addr().IsUnspecified() {
			wild = append(wild, r)
		}
	}
	if len(exact) == 0 {
		exact = wild
	}
	if len(exact) == 0 {
		return socketRow{}, os.ErrNotExist
	}
	if len(exact) > 1 {
		return socketRow{}, errSocketAmbiguous
	}
	return exact[0], nil
}

var errSocketAmbiguous = fmt.Errorf("multiple sockets at local endpoint")
