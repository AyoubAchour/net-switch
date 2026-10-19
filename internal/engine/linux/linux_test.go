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
	for i := 0; i < 100; i++ {
		short, done := context.WithTimeout(ctx, time.Microsecond)
		_, shortErr := o.query(short, unix.AF_INET, unix.IPPROTO_UDP, source, destination)
		done()
		if errors.Is(shortErr, context.DeadlineExceeded) || errors.Is(shortErr, os.ErrDeadlineExceeded) {
			canceled++
		} else if shortErr != nil {
			t.Fatalf("short query: %v", shortErr)
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
	if canceled == 0 {
		t.Fatal("no query was canceled; cancellation path wasn't exercised")
	}
	if len(o.queries.idle) != 1 {
		t.Fatalf("expected a live reusable socket before cleanup, got %d", len(o.queries.idle))
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
	t.Logf("%d canceled queries, 100 fresh matching replies; idle descriptor closed", canceled)
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
	const count = 256
	keys := make(map[netip.AddrPort]bool, count)
	for range count {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
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
	if !o.windows[owner.PID].tailProbed {
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
	_, err = o.holders(ctx, r)
	if !errors.Is(err, platform.ErrAmbiguous) {
		t.Fatalf("two real executable identities must be ambiguous, got %v", err)
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
