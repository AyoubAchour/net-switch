//go:build linux

package linux

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/journal"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

type byteCountingTun struct{ tun.Device }

func newTestOwners(t *testing.T) *Owners {
	t.Helper()
	o := NewOwners()
	t.Cleanup(o.Close)
	return o
}

func TestKernelFileBoundIncludesExactLength(t *testing.T) {
	const path = "/proc/sys/kernel/ostype"
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := readKernelFile(path, len(want))
	if err != nil || string(got) != string(want) {
		t.Fatalf("exact length: %q %v", got, err)
	}
	if _, err := readKernelFile(path, len(want)-1); err == nil {
		t.Fatal("truncation wasn't reported")
	}
}

func TestProcessStartReadsTheKernelFieldAcrossUnusualComm(t *testing.T) {
	b, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	end := strings.LastIndexByte(string(b), ')')
	fields := strings.Fields(string(b[end+1:]))
	want, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	changed := string(b[:strings.IndexByte(string(b), '(')+1]) + "worker ) name\n" + string(b[end:])
	for _, input := range [][]byte{b, []byte(changed)} {
		if got, err := parseProcessStart(input); err != nil || got != want {
			t.Fatalf("start-time field: %d want %d error %v", got, want, err)
		}
	}
	if got, err := processStart(uint32(os.Getpid())); err != nil || got != want {
		t.Fatalf("live process changed identity: %d %v", got, err)
	}
}

func TestDiagnosticPoolCancellationAndClose(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	source := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(c.LocalAddr().(*net.UDPAddr).Port))
	destination := netip.MustParseAddrPort("192.0.2.1:443")
	o := newTestOwners(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var cookie uint64
	canceled := 0
	shortReplies := 0
	for i := 0; i < 100; i++ {
		short, done := context.WithTimeout(ctx, time.Microsecond)
		shortRows, shortErr := o.query(short, unix.AF_INET, unix.IPPROTO_UDP, source, destination)
		done()
		if errors.Is(shortErr, context.DeadlineExceeded) || errors.Is(shortErr, os.ErrDeadlineExceeded) {
			canceled++
		} else if shortErr != nil {
			t.Fatalf("short query: %v", shortErr)
		} else {
			if len(shortRows) != 1 || (cookie != 0 && shortRows[0].cookie != cookie) {
				t.Fatalf("short or recovered reply has the wrong cookie: %+v", shortRows)
			}
			shortReplies++
		}
		rows, err := o.query(ctx, unix.AF_INET, unix.IPPROTO_UDP, source, destination)
		if err != nil || len(rows) != 1 {
			t.Fatalf("query after cancellation %d: %v %v", i, rows, err)
		}
		if cookie != 0 && cookie != rows[0].cookie {
			t.Fatal("reply from another socket")
		}
		cookie = rows[0].cookie
	}
	if len(o.queries.idle) != 1 {
		t.Fatalf("expected a live reusable socket before cleanup, got %d", len(o.queries.idle))
	}
	abandoned := o.queries.idle[0].file
	inner, stop := context.WithCancel(ctx)
	defer stop()
	observed := make(chan diagQueryTrace, 1)
	forced := &cancelBeforeReadContext{Context: inner, cancel: stop, beforeCancel: func() {
		trace := diagQueryTrace{Sequence: diagSequence.Load()}
		trace.peek(abandoned)
		observed <- trace
	}}
	if _, err := o.query(forced, unix.AF_INET, unix.IPPROTO_UDP, source, destination); !errors.Is(err, context.Canceled) {
		t.Fatalf("forced cancellation was not returned: %v", err)
	}
	select {
	case trace := <-observed:
		if !trace.ReplyReady || !trace.ReplyFromKernel || !trace.ReplySequenceMatches || trace.ReplyType != 20 || trace.ReplyCookie != strconv.FormatUint(cookie, 16) {
			t.Fatalf("fixture did not leave its own cookie queued before cancellation: %+v", trace)
		}
	default:
		t.Fatal("fixture did not reach cancellation after its first context check")
	}
	if _, err := abandoned.Stat(); !errors.Is(err, os.ErrClosed) || len(o.queries.idle) != 0 {
		t.Fatalf("canceled query with a queued reply was reused instead of closed: idle=%d err=%v", len(o.queries.idle), err)
	}
	rows, err := o.query(ctx, unix.AF_INET, unix.IPPROTO_UDP, source, destination)
	if err != nil || len(rows) != 1 || rows[0].cookie != cookie || len(o.queries.idle) != 1 {
		t.Fatalf("fresh query after forced cancellation: %+v %v", rows, err)
	}
	live := o.queries.idle[0].file
	if _, err := live.Stat(); err != nil {
		t.Fatalf("socket wasn't open before cleanup: %v", err)
	}
	o.Close()
	if _, err := live.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("pool didn't close its descriptor: %v", err)
	}
	if _, err := o.query(ctx, unix.AF_INET, unix.IPPROTO_UDP, source, destination); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed pool accepted lookup: %v", err)
	}
	t.Logf("short queries: %d deadline failures, %d valid replies; old timing cancellation guard=%t; deterministic queued-reply cancellation and idle cleanup passed", canceled, shortReplies, canceled > 0)
}

func TestTCPReadinessPreservesDataEOFAndClose(t *testing.T) {
	l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	client, err := net.DialTCP("tcp4", nil, l.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := l.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	raw, err := client.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	socket := &tcpSocket{TCPConn: client, raw: raw}
	ready := make(chan error, 1)
	go func() { ready <- socket.WaitReadable(context.Background()) }()
	select {
	case err := <-ready:
		t.Fatalf("idle socket was readable: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if _, err := server.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("data did not wake readiness")
	}
	var data [5]byte
	if _, err := io.ReadFull(socket, data[:]); err != nil || string(data[:]) != "hello" {
		t.Fatalf("peek consumed data: %q %v", data, err)
	}
	server.CloseWrite()
	if err := socket.WaitReadable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := socket.Read(data[:]); err != io.EOF {
		t.Fatalf("EOF lost: %v", err)
	}
	client.Close()
	if err := socket.WaitReadable(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed socket: %v", err)
	}
}

func TestUDPCacheReleasesUnreferencedLiveSockets(t *testing.T) {
	o := newTestOwners(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := o.Warm(ctx); err != nil {
		t.Fatal(err)
	}
	var keys []netip.AddrPort
	var owners []platform.Owner
	var cutoff time.Time
	destination := netip.MustParseAddrPort("192.0.2.1:443")
	for range 2 {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		key := c.LocalAddr().(*net.UDPAddr).AddrPort()
		if len(keys) == 1 {
			cutoff = time.Now()
		}
		v, err := o.UDPFor(ctx, platform.Tuple{Source: key, Destination: destination})
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
		owners = append(owners, v)
	}
	if cookieCacheSize(o) != 2 {
		t.Fatalf("expected both cache entries before reconciliation, got %d", cookieCacheSize(o))
	}
	if _, err := o.SnapshotAt(ctx, keys[:1], cutoff); err != nil || cookieCacheSize(o) != 2 {
		t.Fatalf("lookup completed after enumeration but before dump must survive: %v entries=%d", err, cookieCacheSize(o))
	}
	got, err := o.Snapshot(ctx, keys[:1])
	if err != nil || got[keys[0]] != owners[0] || cookieCacheSize(o) != 1 {
		t.Fatalf("unreferenced cache wasn't released: %v %v entries=%d", got, err, cookieCacheSize(o))
	}
	rows, err := o.query(ctx, unix.AF_INET, unix.IPPROTO_UDP, keys[1], destination)
	if err != nil || len(rows) != 1 || rows[0].generation() != owners[1].Generation {
		t.Fatal("the unreferenced kernel socket must still be alive")
	}
	if _, err := o.UDPFor(ctx, platform.Tuple{Source: keys[1], Destination: destination}); err != nil {
		t.Fatal(err)
	}
	got, err = o.Snapshot(ctx, keys)
	if err != nil || got[keys[1]] != owners[1] || cookieCacheSize(o) != 2 {
		t.Fatalf("referenced pending/active cache lost: %v %v entries=%d", got, err, cookieCacheSize(o))
	}
}

func cookieCacheSize(o *Owners) int {
	count := 0
	for i := range o.index {
		shard := &o.index[i]
		shard.mu.Lock()
		count += len(shard.cookies)
		shard.mu.Unlock()
	}
	return count
}

func TestUDPErrorCallbackUsesTheRealICMPQuote(t *testing.T) {
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	destination := target.LocalAddr().(*net.UDPAddr).AddrPort()
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var optionErr error
	if err := raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVERR, 1) }); err != nil {
		t.Fatal(err)
	}
	if optionErr != nil {
		t.Fatal(optionErr)
	}
	u := &udpSocket{conn: conn, raw: raw, errors: make(chan platform.DatagramError, 1), done: make(chan struct{})}
	var delivered []platform.DatagramError
	u.SetErrorHandler(func(e platform.DatagramError) {
		if !u.errorMu.TryLock() {
			t.Error("callback held the error-queue lock")
		} else {
			u.errorMu.Unlock()
		}
		delivered = append(delivered, e)
	})
	if _, err := u.WriteTo([]byte("icmp quote"), destination, false); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if err := u.WaitReadable(context.Background()); !errors.Is(err, unix.ECONNREFUSED) {
		t.Fatalf("closed peer didn't produce a real ICMP error: %v", err)
	}
	if len(delivered) != 1 || delivered[0].Destination != destination || string(delivered[0].Payload) != "icmp quote" || !delivered[0].Unreachable {
		t.Fatalf("ICMP quote lost its port or payload: %+v", delivered)
	}
}

func TestConcurrentColdHoldersShareDescriptorScans(t *testing.T) {
	const count = 2048
	keys := make(map[netip.AddrPort]bool, count)
	var sockets []*net.UDPConn
	for range count {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		sockets = append(sockets, c)
		keys[c.LocalAddr().(*net.UDPAddr).AddrPort()] = true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := diagDump(ctx, unix.AF_INET, unix.IPPROTO_UDP, netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	o := newTestOwners(t)
	if err := o.Warm(ctx); err != nil {
		t.Fatal(err)
	}
	jobs := make(chan socketRow, count)
	for _, r := range rows {
		if keys[r.local] {
			jobs <- r
		}
	}
	if len(jobs) != count {
		t.Fatalf("expected %d real sockets, found %d", count, len(jobs))
	}
	close(jobs)
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for r := range jobs {
				// The race detector can slow proc scanning; the real 8 ms
				// production deadline is measured by the acceptance gate.
				one, done := context.WithTimeout(ctx, 100*time.Millisecond)
				owner, err := o.holders(one, r)
				done()
				if err != nil || owner.PID != uint32(os.Getpid()) || owner.Generation != r.generation() {
					t.Errorf("cold shared scan: %+v %v", owner, err)
				}
			}
		})
	}
	workers.Wait()
	t.Logf("attributed %d cold socket inodes with 8 concurrent lookups", count)
	descriptor := func(c *net.UDPConn) int {
		raw, err := c.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		fd := -1
		if err := raw.Control(func(value uintptr) { fd = int(value) }); err != nil {
			t.Fatal(err)
		}
		return fd
	}
	old := sockets[count-256]
	oldFD := descriptor(old)
	oldKey := old.LocalAddr().(*net.UDPAddr).AddrPort()
	var oldCookie string
	for _, row := range rows {
		if row.local == oldKey {
			oldCookie = row.generation()
		}
	}
	if oldCookie == "" {
		t.Fatal("old live socket wasn't in the diagnostic dump")
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	reused, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer reused.Close()
	if fd := descriptor(reused); fd != oldFD {
		t.Fatalf("fixture must reuse the descriptor: old %d new %d", oldFD, fd)
	}
	o.mu.Lock()
	window := o.windows[uint32(os.Getpid())]
	o.mu.Unlock()
	t.Logf("reusing fd %d in pid %d, indexed through %d, observed extent %d, last matched fd %d", oldFD, os.Getpid(), window.high, window.extent, window.lastFD)
	source := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(reused.LocalAddr().(*net.UDPAddr).Port))
	beforeFDs, beforeBatches := o.batches.fds.Load(), o.batches.started.Load()
	startedReuse := time.Now()
	tuple := platform.Tuple{Source: source, Destination: netip.MustParseAddrPort("192.0.2.1:443")}
	var newOwner platform.Owner
	if raceInstrumented {
		// Match the initial cold-scanning phase's 100 ms correctness budget
		// under race instrumentation. Real UDPFor and every acceptance probe
		// retain the production 8 ms budget; the normal test below uses it.
		one, done := context.WithTimeout(ctx, 100*time.Millisecond)
		defer done()
		fresh, queryErr := o.query(one, unix.AF_INET, unix.IPPROTO_UDP, tuple.Source, tuple.Destination)
		if queryErr != nil {
			t.Fatal(queryErr)
		}
		row, matchErr := matchUDP(fresh, source)
		if matchErr != nil || row.generation() == "" || row.generation() == oldCookie {
			t.Fatalf("replacement socket query did not prove a new generation: %+v %v", row, matchErr)
		}
		newOwner, err = o.resolveUDP(one, row, false)
		if err == nil && newOwner.Generation != row.generation() {
			t.Fatalf("replacement holder generation %q differs from fresh socket %q", newOwner.Generation, row.generation())
		}
	} else {
		newOwner, err = o.UDPFor(ctx, tuple)
	}
	elapsedReuse := time.Since(startedReuse)
	// Identity keeps the production 8 ms deadline. Report the lookup time even
	// when it expired, but don't gate on it here: the acceptance suite's
	// lookup.p95-measured owns the latency gate.
	unknownIdentity := newOwner.PID == 0 && newOwner.StartTime == 0 && newOwner.Path == "" && newOwner.AppID == ""
	t.Logf("reused descriptor lookup: %s, %d scanned FDs in %d batches; race-instrumented=%t original-8ms-verdict=%t unknown-identity=%t", elapsedReuse, o.batches.fds.Load()-beforeFDs, o.batches.started.Load()-beforeBatches, raceInstrumented, err == nil && elapsedReuse <= 8*time.Millisecond, unknownIdentity)
	// A reused descriptor must never answer with the previous holder's
	// identity. That is never a timing outcome, so it fails immediately.
	if newOwner.Generation == oldCookie || (newOwner.PID != 0 && newOwner.PID != uint32(os.Getpid())) {
		t.Fatalf("reused descriptor inherited stale identity: %+v %v", newOwner, err)
	}
	// Identity can miss its production deadline on a loaded runner. The engine
	// then admits the socket's generation with an unknown identity, which is the
	// designed outcome, not a stale identity. Only in that exact case, confirm
	// the replacement owner once with this test's 100 ms correctness budget and
	// log both durations, so real slowness stays visible.
	if unknownIdentity && newOwner.Generation != "" && errors.Is(err, context.DeadlineExceeded) {
		confirmCtx, confirmDone := context.WithTimeout(ctx, 100*time.Millisecond)
		defer confirmDone()
		liveRows, dumpErr := diagDump(confirmCtx, unix.AF_INET, unix.IPPROTO_UDP, source)
		if dumpErr != nil {
			t.Fatalf("replacement socket query after the identity deadline expired: %v", dumpErr)
		}
		live, matchErr := matchUDP(liveRows, source)
		if matchErr != nil {
			t.Fatalf("replacement socket lookup after the identity deadline expired: %v", matchErr)
		}
		if live.generation() == oldCookie || live.generation() != newOwner.Generation {
			t.Fatalf("expired-identity lookup reported generation %q, replacement socket is %q (previous %q)", newOwner.Generation, live.generation(), oldCookie)
		}
		retryStarted := time.Now()
		newOwner, err = o.resolveUDP(confirmCtx, live, false)
		t.Logf("reused descriptor identity retry: %s after the production lookup took %s and left generation %s unknown; re-resolved with 100ms", time.Since(retryStarted), elapsedReuse, live.generation())
	}
	if err != nil || newOwner.PID != uint32(os.Getpid()) || newOwner.Generation == oldCookie {
		t.Fatalf("reused descriptor inherited stale identity or wasn't found: %+v %v", newOwner, err)
	}
}

func (*byteCountingTun) Write(p [][]byte, offset int) (int, error) {
	return len(p[0]) - offset + 10, nil
}
func TestLinuxTunWriteReturnsBytes(t *testing.T) {
	d := &Tun{device: &byteCountingTun{}}
	if err := d.WritePacket(context.Background(), make([]byte, 60)); err != nil {
		t.Fatalf("successful Linux TUN write must not terminate forwarding: %v", err)
	}
}

func TestDiagCookieAndCgroup(t *testing.T) {
	b := make([]byte, 84)
	b[0] = unix.AF_INET
	binary.BigEndian.PutUint16(b[4:], 1234)
	binary.BigEndian.PutUint16(b[6:], 443)
	copy(b[8:], []byte{192, 0, 2, 1})
	copy(b[24:], []byte{198, 51, 100, 1})
	binary.NativeEndian.PutUint32(b[44:], 0x12345678)
	binary.NativeEndian.PutUint32(b[48:], 0x90abcdef)
	binary.NativeEndian.PutUint32(b[64:], 1000)
	binary.NativeEndian.PutUint32(b[68:], 42)
	binary.NativeEndian.PutUint16(b[72:], 12)
	binary.NativeEndian.PutUint16(b[74:], 21)
	binary.NativeEndian.PutUint64(b[76:], 123456)
	r, err := parseDiag(b)
	if err != nil {
		t.Fatal(err)
	}
	if r.local != netip.MustParseAddrPort("192.0.2.1:1234") || r.cookie != 0x90abcdef12345678 || r.cgroup != 123456 || r.inode != 42 || r.uid != 1000 {
		t.Fatalf("bad diag row: %+v", r)
	}
	binary.NativeEndian.PutUint16(b[72:], 100)
	if _, err := parseDiag(b); err == nil {
		t.Fatal("accepted truncated attribute")
	}
}

func TestSequentialColdSocketsReuseLowDescriptors(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	o := newTestOwners(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := 0; i < 100; i++ {
		c, err := net.Dial("tcp4", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		source := c.LocalAddr().(*net.TCPAddr).AddrPort()
		destination := c.RemoteAddr().(*net.TCPAddr).AddrPort()
		rows, err := diag(ctx, unix.AF_INET, unix.IPPROTO_TCP, source, destination, false)
		if err != nil || len(rows) != 1 {
			c.Close()
			t.Fatalf("cold socket %d: diag %v %v", i, rows, err)
		}
		owner, err := o.holders(ctx, rows[0])
		c.Close()
		if err != nil || owner.PID != uint32(os.Getpid()) {
			t.Fatalf("cold socket %d after descriptor reuse: %+v %v", i, owner, err)
		}
	}
}

func TestSocketBeyondFiveThousandRegularFiles(t *testing.T) {
	var files []*os.File
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	for i := 0; i < 5000; i++ {
		f, err := os.Open("/dev/null")
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	key := c.LocalAddr().(*net.UDPAddr).AddrPort()
	rows, err := diagDump(ctx, unix.AF_INET, unix.IPPROTO_UDP, key)
	if err != nil {
		t.Fatal(err)
	}
	r, err := matchUDP(rows, key)
	if err != nil {
		t.Fatal(err)
	}
	o := newTestOwners(t)
	owner, err := o.holders(ctx, r)
	if err != nil || owner.PID != uint32(os.Getpid()) {
		t.Fatalf("socket after 5,000 files: %+v %v", owner, err)
	}
	o.mu.Lock()
	tailProbed := o.windows[owner.PID].tailProbed
	o.mu.Unlock()
	if !tailProbed {
		t.Fatal("lookup didn't use the bounded descriptor-tail search")
	}
}

func TestRuleActionAndOneByteProtocol(t *testing.T) {
	b := make([]byte, 20)
	b[0] = unix.AF_INET
	b[4] = 254
	b[7] = 1
	binary.NativeEndian.PutUint16(b[12:], 5)
	binary.NativeEndian.PutUint16(b[14:], 22)
	b[16] = 17
	r, err := parseRule(b)
	if err != nil || r.rule.Type != 1 || r.rule.Table != 254 || r.rule.IPProto != 17 || len(r.extra) != 0 {
		t.Fatalf("UAPI rule: %+v %v", r, err)
	}
	b[7] = 7
	r, err = parseRule(b)
	if err != nil || r.rule.Type != 7 {
		t.Fatalf("action was lost: %+v %v", r, err)
	}
}

func TestRealUDPDiagAndConflictingLiveHolders(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	key := c.LocalAddr().(*net.UDPAddr).AddrPort()
	rows, err := diagDump(ctx, unix.AF_INET, unix.IPPROTO_UDP, key)
	if err != nil {
		t.Fatal(err)
	}
	r, err := matchUDP(rows, key)
	if err != nil {
		t.Fatal(err)
	}
	if r.cookie == 0 || r.inode == 0 {
		t.Fatalf("socket lacks kernel identity: %+v", r)
	}
	o := newTestOwners(t)
	owner, err := o.holders(ctx, r)
	if err != nil || owner.PID != uint32(os.Getpid()) || owner.StartTime == 0 || owner.Generation == "" {
		t.Fatalf("live owner: %+v %v", owner, err)
	}
	f, err := c.File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	child := exec.Command("sleep", "20")
	child.ExtraFiles = []*os.File{f}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { child.Process.Kill(); child.Wait() }()
	owner, err = o.resolveUDP(ctx, r, false)
	if !errors.Is(err, platform.ErrAmbiguous) || owner != (platform.Owner{Generation: r.generation()}) {
		t.Fatalf("two real executable identities must retain only their cookie and ambiguity, got %+v %v", owner, err)
	}
	child.Process.Kill()
	child.Wait()
	owner, err = o.holders(ctx, r)
	if err != nil || owner.PID != uint32(os.Getpid()) {
		t.Fatalf("after other holder exits: %+v %v", owner, err)
	}
}

func TestUDPEndpointPreferenceAndAmbiguity(t *testing.T) {
	key := netip.MustParseAddrPort("198.18.0.1:12345")
	wild := socketRow{local: netip.MustParseAddrPort("0.0.0.0:12345"), cookie: 1}
	exact := socketRow{local: key, cookie: 2}
	r, err := matchUDP([]socketRow{wild, exact}, key)
	if err != nil || r.cookie != 2 {
		t.Fatalf("exact must win: %+v %v", r, err)
	}
	other := wild
	other.cookie = 3
	_, err = matchUDP([]socketRow{wild, other}, key)
	if !errors.Is(err, errSocketAmbiguous) {
		t.Fatalf("wildcard reuse: %v", err)
	}
	if _, err := matchUDP([]socketRow{wild, wild}, key); err != nil {
		t.Fatalf("repeated dump row isn't a second socket: %v", err)
	}
	first := cookieSet([]socketRow{wild, other}, key)
	if first != cookieSet([]socketRow{other, wild, wild}, key) {
		t.Fatal("cookie set depends on dump ordering or duplicate rows")
	}
	if first == cookieSet([]socketRow{wild}, key) {
		t.Fatal("cookie set didn't change when a socket closed")
	}
}

func TestDualStackUDPOwnerAndReconciliation(t *testing.T) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	key := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(c.LocalAddr().(*net.UDPAddr).Port))
	client, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(key))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("dual-stack")); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 32)
	if _, _, err := c.ReadFromUDP(b); err != nil {
		t.Fatal(err)
	}
	o := newTestOwners(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := o.Warm(ctx); err != nil {
		t.Fatal(err)
	}
	owner, err := o.UDP(ctx, key)
	if err != nil || owner.PID != uint32(os.Getpid()) || owner.Generation == "" {
		t.Fatalf("dual-stack IPv4 owner: %+v %v", owner, err)
	}
	rows, err := o.Snapshot(ctx, []netip.AddrPort{key})
	if err != nil || rows[key] != owner {
		t.Fatalf("dual-stack identity: %+v %v", rows, err)
	}
}

func TestUDPFirstDestinationUsesOneExactQuery(t *testing.T) {
	for _, connected := range []bool{false, true} {
		t.Run(fmt.Sprint(connected), func(t *testing.T) {
			server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			var client *net.UDPConn
			if connected {
				client, err = net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
			} else {
				client, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
			}
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			source := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(client.LocalAddr().(*net.UDPAddr).Port))
			tuple := platform.Tuple{Source: source, Destination: server.LocalAddr().(*net.UDPAddr).AddrPort()}
			o := newTestOwners(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := o.Warm(ctx); err != nil {
				t.Fatal(err)
			}
			before := diagSequence.Load()
			owner, err := o.UDPFor(ctx, tuple)
			if err != nil || owner.PID != uint32(os.Getpid()) {
				t.Fatalf("exact UDP ownership: %+v %v", owner, err)
			}
			if requests := diagSequence.Load() - before; requests != 1 {
				t.Fatalf("new UDP socket used %d diagnostic requests; expected one exact lookup", requests)
			}
		})
	}
}

func TestHoldSameProgramSocket(t *testing.T) {
	if os.Getenv("NETSWITCH_TEST_HOLD_SOCKET") != "1" {
		t.Skip("inherited socket helper")
	}
	f := os.NewFile(3, "inherited UDP socket")
	defer f.Close()
	fmt.Println("ready")
	io.Copy(io.Discard, os.Stdin)
}

func TestSameAppHoldersKeepAStableRepresentative(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	f, err := c.File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	child := exec.Command(os.Args[0], "-test.run=^TestHoldSameProgramSocket$")
	child.Env = append(os.Environ(), "NETSWITCH_TEST_HOLD_SOCKET=1")
	child.ExtraFiles = []*os.File{f}
	input, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { input.Close(); child.Process.Kill(); child.Wait() }()
	if line, err := bufio.NewReader(output).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("socket holder: %q %v", line, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	key := c.LocalAddr().(*net.UDPAddr).AddrPort()
	rows, err := diagDump(ctx, unix.AF_INET, unix.IPPROTO_UDP, key)
	if err != nil {
		t.Fatal(err)
	}
	r, err := matchUDP(rows, key)
	if err != nil {
		t.Fatal(err)
	}
	o := newTestOwners(t)
	owner, err := o.holders(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	identities, err := o.Snapshot(ctx, []netip.AddrPort{key})
	if err != nil || identities[key] != owner {
		t.Fatalf("unchanged same-app holders changed socket identity: before %+v after %+v error %v", owner, identities[key], err)
	}
}

func TestOwnershipStoreTornTailAndCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal")
	s := diskStore{path}
	r := journal.Record{ID: "one", Boot: "boot", Instance: "instance", Kind: "route", Fingerprint: journal.Fingerprint{"table": "21001"}, Phase: "intent"}
	if err := s.Append(r); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("{\"record\":")
	f.Close()
	records, err := s.Records()
	if err != nil || len(records) != 1 {
		t.Fatalf("torn tail recovery: %v %v", records, err)
	}
	r.Phase = "created"
	if err := s.Append(r); err != nil {
		t.Fatal(err)
	}
	records, err = s.Records()
	if err != nil || len(records) != 2 {
		t.Fatalf("append after recovery: %v %v", records, err)
	}
	bad, _ := json.Marshal(diskRecord{json.RawMessage(`{"id":"bad"}`), "not a checksum"})
	f, _ = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.Write(append(bad, '\n'))
	f.Close()
	if _, err := s.Records(); err == nil {
		t.Fatal("complete corrupt record accepted")
	}
}

func TestJournalRefusesLinksAndUnsafePermissions(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	path := filepath.Join(dir, "journal")
	if err := os.WriteFile(target, []byte("must survive"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := (diskStore{path}).Records(); err == nil {
		t.Fatal("followed journal symlink")
	}
	os.Remove(path)
	if err := os.Link(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := (diskStore{path}).Records(); err == nil {
		t.Fatal("accepted multiply linked journal")
	}
	os.Remove(path)
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := (diskStore{path}).Records(); err == nil {
		t.Fatal("accepted readable-by-others journal")
	}
	b, err := os.ReadFile(target)
	if err != nil || string(b) != "must survive" {
		t.Fatalf("unsafe target was changed: %q %v", b, err)
	}
}

func TestLifetimeLockExcludesCleanup(t *testing.T) {
	l := fileLock{filepath.Join(t.TempDir(), "lock")}
	release, err := l.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if other, err := l.Acquire(ctx); err == nil {
		other()
		t.Fatal("cleanup acquired a live engine's lock")
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	release, err = l.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release()
}

func TestCleanupInWrongNamespaceKeepsTheJournal(t *testing.T) {
	o := &objects{boot: "same-boot", netns: "current"}
	fp := journal.Fingerprint{"boot": "same-boot", "netns": "other", "object": "{}"}
	if _, _, err := (objectDriver{o, "route"}).Inspect(context.Background(), fp); err == nil {
		t.Fatal("wrong-namespace cleanup treated an uninspected object as missing")
	}
	fp["boot"] = "previous-boot"
	if _, found, err := (objectDriver{o, "route"}).Inspect(context.Background(), fp); err != nil || found {
		t.Fatalf("objects from a previous boot must be gone: %v %v", found, err)
	}
}

func TestLayoutMovesAsAWhole(t *testing.T) {
	mask := ^uint32(0)
	rules := []netlink.Rule{{Priority: 10001, Mark: 0x4e530001, Mask: &mask, Table: 21001}}
	if layoutAvailable(0, 255, rules, nil) {
		t.Fatal("accepted occupied priority/table/mark")
	}
	if !layoutAvailable(1000, 255, rules, nil) {
		t.Fatal("whole shifted layout unavailable")
	}
	mask = 0xffff0000
	if layoutAvailable(1000, 255, rules, nil) {
		t.Fatal("ignored overlapping masked mark selector")
	}
}
