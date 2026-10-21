//go:build linux

package linux

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type socketRow struct {
	protocol       int
	v6only         bool
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
	r.local = netip.AddrPortFrom(a.Unmap(), binary.BigEndian.Uint16(b[4:6]))
	r.remote = netip.AddrPortFrom(z.Unmap(), binary.BigEndian.Uint16(b[6:8]))
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
		if kind == 11 && n >= 5 {
			r.v6only = b[off+4] != 0
		}
		off += (n + 3) &^ 3
	}
	return r, nil
}

var diagDumpBuffers = sync.Pool{New: func() any { b := make([]byte, 64<<10); return &b }}

var diagSequence atomic.Uint32

func diag(ctx context.Context, family, protocol int, local, remote netip.AddrPort, dump bool) ([]socketRow, error) {
	return diagQuery(ctx, family, protocol, local, remote, dump, nil)
}

// Only completed exact queries are reusable. Interrupted dumps, cancellation,
// malformed messages and errors discard the descriptor with all pending data.
func diagQuery(ctx context.Context, family, protocol int, local, remote netip.AddrPort, dump bool, pool *diagPool) (rows []socketRow, err error) {
	trace := diagQueryTrace{Stage: "context", StartedNS: time.Now().UnixNano()}
	if deadline, ok := ctx.Deadline(); ok {
		trace.DeadlineNS = deadline.UnixNano()
	}
	defer func() {
		if err != nil {
			trace.CompletedNS = time.Now().UnixNano()
			err = &diagQueryError{Trace: trace, cause: err}
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	trace.Stage = "socket"
	connection, err := pool.get()
	if err != nil {
		return nil, err
	}
	f, fd := connection.file, connection.fd
	trace.SocketReadyNS = time.Now().UnixNano()
	deadline, timed := ctx.Deadline()
	var canceled chan struct{}
	var stop func() bool
	lateReply := false
	// A lookup's native read deadline is already at most 8 ms. It needs no
	// extra cancellation goroutine/channel; cancellation still finishes
	// inside that budget. Longer dumps retain immediate cancellation.
	if dump || !timed || time.Until(deadline) > 10*time.Millisecond {
		canceled = make(chan struct{})
		stop = context.AfterFunc(ctx, func() { f.SetReadDeadline(time.Now()); close(canceled) })
	}
	defer func() {
		if !dump && trace.Stage == "receive" && (errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded)) {
			trace.peek(f)
		}
		// A cancellation callback must finish before a later borrower can
		// install its own deadline on this same descriptor.
		if stop != nil && !stop() {
			<-canceled
		}
		if err != nil || dump || lateReply || ctx.Err() != nil {
			f.Close()
			return
		}
		if f.SetReadDeadline(time.Time{}) != nil {
			f.Close()
			return
		}
		pool.put(connection)
	}()
	if timed {
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
	sequence := diagSequence.Add(1)
	trace.Sequence = sequence
	binary.NativeEndian.PutUint32(b[8:], sequence)
	b[16] = byte(family)
	b[17] = byte(protocol)
	binary.NativeEndian.PutUint32(b[20:], ^uint32(0))
	// UDP's exact query uses the inbound lookup convention (remote,local).
	if protocol == unix.IPPROTO_UDP && !dump {
		local, remote = remote, local
	}
	if family == unix.AF_INET6 {
		if local.IsValid() && local.Addr().Is4() {
			local = netip.AddrPortFrom(netip.AddrFrom16(local.Addr().As16()), local.Port())
		}
		if remote.IsValid() && remote.Addr().Is4() {
			remote = netip.AddrPortFrom(netip.AddrFrom16(remote.Addr().As16()), remote.Port())
		}
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
	trace.Stage = "send"
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	trace.SentNS = time.Now().UnixNano()
	buf := connection.buffer[:]
	if dump {
		pooled := diagDumpBuffers.Get().(*[]byte)
		defer diagDumpBuffers.Put(pooled)
		buf = *pooled
	}
	for {
		if lateReply {
			// One ready packet is the complete salvage budget. An unrelated
			// control message cannot keep an expired query reading forever.
			return nil, context.DeadlineExceeded
		}
		trace.Stage, trace.ReadStartedNS = "receive", time.Now().UnixNano()
		var n int
		var readErr error
		if dump {
			n, readErr = readNetlink(f, buf)
		} else {
			n, lateReply, readErr = readExactNetlink(ctx, f, buf)
		}
		err := readErr
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
		trace.Stage = "parse"
		messages, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, err
		}
		for _, m := range messages {
			if m.Header.Seq != sequence {
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
				r.protocol = protocol
				rows = append(rows, r)
				if !dump {
					if lateReply && pool != nil {
						pool.lateReplies.Add(1)
					}
					return rows, nil
				}
			case unix.NLMSG_OVERRUN:
				return nil, unix.ENOBUFS
			}
		}
	}
}

func readNetlink(f *os.File, b []byte) (int, error) {
	return receiveNetlink(f, b, true)
}

// RawRead checks its deadline before recvmsg, even when the exact response
// is already queued by Sendto. Retrieve that one ready response without a
// new request, wait or deadline reset. Owner resolution still checks the same
// absolute deadline even before the context timer updates Err(), so this
// preserves a cookie, never an overdue identity.
// Dumps must not use this: a ready multipart stream could bypass its deadline.
func readExactNetlink(ctx context.Context, f *os.File, b []byte) (int, bool, error) {
	if errors.Is(ctx.Err(), context.Canceled) {
		return 0, false, context.Canceled
	}
	n, err := readNetlink(f, b)
	if errors.Is(ctx.Err(), context.Canceled) {
		return 0, false, context.Canceled
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, context.DeadlineExceeded) {
		return n, false, err
	}
	n, readyErr := receiveNetlink(f, b, false)
	if errors.Is(ctx.Err(), context.Canceled) {
		return 0, true, context.Canceled
	}
	if errors.Is(readyErr, unix.EAGAIN) || errors.Is(readyErr, unix.EWOULDBLOCK) {
		return 0, true, err
	}
	return n, true, readyErr
}

func receiveNetlink(f *os.File, b []byte, wait bool) (int, error) {
	raw, err := f.SyscallConn()
	if err != nil {
		return 0, err
	}
	var n, flags int
	var from unix.Sockaddr
	var readErr error
	receive := func(fd uintptr) bool {
		n, _, flags, from, readErr = unix.Recvmsg(int(fd), b, nil, unix.MSG_DONTWAIT)
		return !errors.Is(readErr, unix.EAGAIN) && !errors.Is(readErr, unix.EWOULDBLOCK)
	}
	if wait {
		err = raw.Read(receive)
	} else {
		err = raw.Control(func(fd uintptr) { receive(fd) })
	}
	if err != nil {
		return 0, err
	}
	if readErr != nil {
		return 0, readErr
	}
	if flags&unix.MSG_TRUNC != 0 {
		return 0, unix.ENOBUFS
	}
	peer, ok := from.(*unix.SockaddrNetlink)
	if !ok || peer.Pid != 0 {
		return 0, errors.New("netlink response is not from the kernel")
	}
	return n, nil
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
	exact := udpCandidates(rows, source)
	if len(exact) == 0 {
		return socketRow{}, os.ErrNotExist
	}
	if len(exact) > 1 {
		return socketRow{}, errSocketAmbiguous
	}
	return exact[0], nil
}

func udpCandidates(rows []socketRow, source netip.AddrPort) []socketRow {
	var exact, wild []socketRow
	seen := map[uint64]bool{}
	for _, r := range rows {
		if r.local.Port() != source.Port() || seen[r.cookie] {
			continue
		}
		seen[r.cookie] = true
		dual := source.Addr().Is4() && r.local.Addr() == netip.IPv6Unspecified() && !r.v6only
		if !dual && r.local.Addr().BitLen() != source.Addr().BitLen() {
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
	return exact
}

// An ambiguous endpoint still follows unknown-owner policy. Its generation
// covers the complete cookie set, so it cannot retain that policy when any
// member closes or is replaced. The public generation remains an opaque ID.
func cookieSet(rows []socketRow, source netip.AddrPort) string {
	candidates := udpCandidates(rows, source)
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].cookie < candidates[j].cookie })
	h := sha256.New()
	var b [8]byte
	for _, r := range candidates {
		binary.BigEndian.PutUint64(b[:], r.cookie)
		h.Write(b[:])
	}
	return "cookies:" + hex.EncodeToString(h.Sum(nil))
}

var errSocketAmbiguous = fmt.Errorf("multiple sockets at local endpoint")
