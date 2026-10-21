//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"golang.org/x/sys/unix"
)

// Cancellation is real; only the point where it occurs is deterministic.
// The first Err check admits the query, and the next checks its queued reply
// before canceling. An earlier extra check would fail the fixture's proof.
type cancelBeforeReadContext struct {
	context.Context
	cancel       context.CancelFunc
	beforeCancel func()
	checks       atomic.Int32
}

func (c *cancelBeforeReadContext) Err() error {
	if c.checks.Add(1) == 2 {
		c.beforeCancel()
		c.cancel()
	}
	return c.Context.Err()
}

// Model the valid interval between an absolute deadline and its timer
// goroutine closing Done. Err stays nil while Done remains open.
type pendingDeadlineContext struct {
	context.Context
	deadline time.Time
	done     chan struct{}
}

func (c pendingDeadlineContext) Deadline() (time.Time, bool) { return c.deadline, true }
func (c pendingDeadlineContext) Done() <-chan struct{}       { return c.done }

func TestLateExactReplyCannotUseCachedIdentityBeforeContextTimerRuns(t *testing.T) {
	app, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	tuple := platform.Tuple{Source: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), app.LocalAddr().(*net.UDPAddr).AddrPort().Port()), Destination: netip.MustParseAddrPort("192.0.2.1:443")}
	o := newTestOwners(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := o.Warm(ctx); err != nil {
		t.Fatal(err)
	}
	known, err := o.UDPFor(ctx, tuple)
	if err != nil || known.PID != uint32(os.Getpid()) || known.AppID == "" || known.Generation == "" {
		t.Fatalf("fixture must first establish a cached real owner: %+v %v", known, err)
	}
	if len(o.queries.idle) != 1 {
		t.Fatalf("fixture has %d idle query sockets, want one", len(o.queries.idle))
	}
	previous := o.queries.idle[0].file
	before := o.Stats().(lookupStats)
	late := pendingDeadlineContext{Context: context.Background(), deadline: time.Now().Add(-time.Second), done: make(chan struct{})}
	owner, err := o.UDPFor(late, tuple)
	if !errors.Is(err, context.DeadlineExceeded) || owner.Generation != known.Generation || owner.PID != 0 || owner.AppID != "" || owner.Path != "" || late.Err() != nil {
		t.Fatalf("absolute deadline allowed overdue cached identity or lost its cookie: %+v %v parentErr=%v", owner, err, late.Err())
	}
	after := o.Stats().(lookupStats)
	if after.ExactRepliesAfterDeadline != before.ExactRepliesAfterDeadline+1 || after.ExpiredBeforeHolderScan != before.ExpiredBeforeHolderScan+1 || after.HolderTimeouts != before.HolderTimeouts {
		t.Fatalf("late reply was not distinguished from a scan timeout: before=%+v after=%+v", before, after)
	}
	if _, err := previous.Stat(); !errors.Is(err, os.ErrClosed) || len(o.queries.idle) != 0 {
		t.Fatalf("recovered late query socket was pooled: idle=%d err=%v", len(o.queries.idle), err)
	}
}

func TestExpiredNetlinkDeadlinePreservesReadyExactReply(t *testing.T) {
	// The isolated kernel-test namespace can begin with loopback down.
	// A wildcard socket needs no configured interface or outbound traffic.
	app, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	source := app.LocalAddr().(*net.UDPAddr).AddrPort()
	remote := netip.MustParseAddrPort("192.0.2.1:443")
	socket, err := (*diagPool)(nil).get()
	if err != nil {
		t.Fatal(err)
	}
	defer socket.file.Close()
	// An exact UDP diagnostic request uses the kernel's incoming convention.
	var request [72]byte
	const sequence = 0x51444745
	binary.NativeEndian.PutUint32(request[:], uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:], 20)
	binary.NativeEndian.PutUint16(request[6:], unix.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(request[8:], sequence)
	request[16], request[17] = unix.AF_INET, unix.IPPROTO_UDP
	binary.NativeEndian.PutUint32(request[20:], ^uint32(0))
	binary.BigEndian.PutUint16(request[24:], remote.Port())
	binary.BigEndian.PutUint16(request[26:], source.Port())
	copy(request[28:44], remote.Addr().AsSlice())
	copy(request[44:60], source.Addr().AsSlice())
	for i := 64; i < len(request); i++ {
		request[i] = 255
	}
	if err := unix.Sendto(socket.fd, request[:], 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	poll := []unix.PollFd{{Fd: int32(socket.fd), Events: unix.POLLIN}}
	if n, err := unix.Poll(poll, 1000); err != nil || n != 1 || poll[0].Revents&unix.POLLIN == 0 {
		t.Fatalf("kernel reply was not queued before the expired read: n=%d events=%d err=%v", n, poll[0].Revents, err)
	}
	if err := socket.file.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	var data [4096]byte
	if n, err := readNetlink(socket.file, data[:]); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("RawRead oracle did not reject the ready reply at its expired deadline: n=%d err=%v", n, err)
	}
	var peekCookie string
	for range 2 {
		trace := diagQueryTrace{Sequence: sequence}
		trace.peek(socket.file)
		if !trace.ReplyReady || !trace.ReplyFromKernel || !trace.ReplySequenceMatches || trace.ReplyType != 20 || trace.ReplyCookie == "" || trace.PeekError != "" {
			t.Fatalf("diagnostic peek lost or consumed the queued reply: %+v", trace)
		}
		peekCookie = trace.ReplyCookie
	}
	canceled, stop := context.WithCancel(t.Context())
	stop()
	if n, late, err := readExactNetlink(canceled, socket.file, data[:]); n != 0 || late || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation must win without reading the packet: n=%d late=%t err=%v", n, late, err)
	}
	expired, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	n, late, err := readExactNetlink(expired, socket.file, data[:])
	if err != nil || !late || !errors.Is(expired.Err(), context.DeadlineExceeded) {
		t.Fatalf("one ready response was lost or its deadline was changed: n=%d late=%t err=%v ctx=%v", n, late, err, expired.Err())
	}
	messages, err := syscall.ParseNetlinkMessage(data[:n])
	if err != nil || len(messages) != 1 || messages[0].Header.Seq != sequence || messages[0].Header.Type != 20 {
		t.Fatalf("queued message was not this socket's exact kernel answer: %+v %v", messages, err)
	}
	row, err := parseDiag(messages[0].Data)
	if err != nil || row.local != source || row.cookie == 0 || row.generation() != peekCookie {
		t.Fatalf("queued answer had no independently live socket cookie: %+v %v", row, err)
	}
	o := NewOwners()
	defer o.Close()
	owner, err := o.resolveUDP(expired, row, false)
	if !errors.Is(err, context.DeadlineExceeded) || owner.Generation != row.generation() || owner.PID != 0 || owner.AppID != "" || owner.Path != "" {
		t.Fatalf("late cookie must retain the timeout and never supply identity: %+v %v", owner, err)
	}
	if n, err := readNetlink(socket.file, data[:]); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ready receive reset the native deadline: n=%d err=%v", n, err)
	}
	if n, _, err := readExactNetlink(expired, socket.file, data[:]); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("empty queue did not preserve the timeout: n=%d err=%v", n, err)
	}
	// The ready path must retain the ordinary receiver's truncation check.
	if err := unix.Sendto(socket.fd, request[:], 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	if n, _, err := readExactNetlink(expired, socket.file, data[:16]); n != 0 || !errors.Is(err, unix.ENOBUFS) {
		t.Fatalf("truncated ready response was accepted: n=%d err=%v", n, err)
	}
	t.Logf("expired RawRead hid ready kernel response for %s cookie=%s; one nonblocking receive preserved the cookie with unknown identity and unchanged deadline", source, row.generation())
}

func TestUDPGenerationFailureHistoryIsBounded(t *testing.T) {
	o := NewOwners()
	defer o.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	for i := range 20 {
		tuple := platform.Tuple{Source: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(10000+i)), Destination: netip.MustParseAddrPort("192.0.2.1:443")}
		o.recordUDPGenerationFailure(ctx, tuple, "exact-query", time.Now(), &diagQueryError{Trace: diagQueryTrace{Stage: "receive", Sequence: uint32(i)}, cause: context.DeadlineExceeded})
	}
	stats := o.Stats().(lookupStats)
	if len(stats.UDPGenerationFailures) != 8 {
		t.Fatalf("retained %d failures, want 8", len(stats.UDPGenerationFailures))
	}
	seen := map[uint16]bool{}
	for _, failure := range stats.UDPGenerationFailures {
		port := failure.Tuple.Source.Port()
		if port < 10012 || port > 10019 || seen[port] || failure.Query == nil || failure.Query.Stage != "receive" || failure.DeadlineNS == 0 {
			t.Fatalf("failure evidence was lost or retained past its bound: %+v", failure)
		}
		seen[port] = true
	}
}
