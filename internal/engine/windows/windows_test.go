//go:build windows

package winengine

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/journal"
	"github.com/AyoubAchour/net-switch/internal/wintun"
	"golang.org/x/sys/windows"
)

func hosted(t *testing.T) {
	t.Helper()
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Skip("Windows runtime checks run on disposable hosted CI only")
	}
}

func TestCaptureComplement(t *testing.T) {
	prefixes := CapturePrefixes()
	for i, p := range prefixes {
		for _, q := range prefixes[i+1:] {
			if p.Overlaps(q) {
				t.Fatalf("capture overlap %s %s", p, q)
			}
		}
		for _, q := range localRanges {
			if p.Overlaps(q) {
				t.Fatalf("captured local range %s %s", p, q)
			}
		}
	}
	for _, text := range []string{"1.1.1.1", "8.8.8.8", "100.64.0.1", "127.0.0.1", "198.19.128.2", "2001:db8:198::2", "2606:4700:4700::1111"} {
		addr := netip.MustParseAddr(text)
		if !slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(addr) }) {
			t.Fatal("public address omitted", addr)
		}
	}
}

func TestRouteInitializationMatchesFingerprint(t *testing.T) {
	hosted(t)
	var initialized windows.MibIpForwardRow2
	iphlp.NewProc("InitializeIpForwardEntry").Call(uintptr(unsafe.Pointer(&initialized)))
	t.Logf("Windows route defaults: loopback=%d autoconfigure=%d publish=%d immortal=%d", initialized.Loopback, initialized.AutoconfigureAddress, initialized.Publish, initialized.Immortal)
	fp := journal.Fingerprint{"guid": wintun.DefaultGUID, "luid": "1", "index": "1", "prefix": "1.0.0.0/8", "nextHop": "0.0.0.0", "metric": "0", "protocol": "3"}
	row := routeRow(fp)
	if row.Loopback != 0 || row.AutoconfigureAddress != 0 || row.Publish != 0 || row.SitePrefixLength != 0 || row.Immortal != 1 {
		t.Fatalf("route creation disagrees with its ownership fingerprint: %+v", row)
	}
}

func TestIPPathABI(t *testing.T) {
	var row pathRow
	if unsafe.Sizeof(row) != 136 || unsafe.Offsetof(row.LUID) != 56 || unsafe.Offsetof(row.MTU) != 96 {
		t.Fatalf("unexpected MIB_IPPATH_ROW layout: size=%d luid=%d mtu=%d", unsafe.Sizeof(row), unsafe.Offsetof(row.LUID), unsafe.Offsetof(row.MTU))
	}
}

func TestTCPTableIncludesSYNSentAndSkipsZeroPID(t *testing.T) {
	raw := make([]byte, 4+2*24)
	binary.LittleEndian.PutUint32(raw, 2)
	for i := range 2 {
		r := raw[4+i*24:]
		binary.LittleEndian.PutUint32(r, 3) // MIB_TCP_STATE_SYN_SENT.
		copy(r[4:], []byte{198, 18, 0, 1})
		binary.BigEndian.PutUint16(r[8:], uint16(40000+i))
		copy(r[12:], []byte{1, 1, 1, 1})
		binary.BigEndian.PutUint16(r[16:], 443)
	}
	binary.LittleEndian.PutUint32(raw[4+20:], 123)
	rows := map[platform.Tuple]tcpCandidates{}
	if err := parseTCP(raw, false, rows); err != nil {
		t.Fatal(err)
	}
	key := platform.Tuple{Source: netip.MustParseAddrPort("198.18.0.1:40000"), Destination: netip.MustParseAddrPort("1.1.1.1:443")}
	if len(rows) != 1 || rows[key] != (tcpCandidates{pid: 123, count: 1}) {
		t.Fatal(rows)
	}
	if err := parseTCP(raw[:len(raw)-1], false, rows); err == nil {
		t.Fatal("accepted partial TCP table")
	}
	copy(raw[4+24:], raw[4:4+24])
	binary.LittleEndian.PutUint32(raw[4+24+20:], 456)
	clear(rows)
	if err := parseTCP(raw, false, rows); err != nil || len(rows) != 1 || rows[key].count != 2 {
		t.Fatalf("lost ambiguous exact tuple: %v %v", rows, err)
	}
}

func TestUDPModuleABIAndAmbiguity(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		stride, pidOffset, timeOffset, portOffset := 160, 8, 16, 4
		ip := netip.MustParseAddr("198.18.0.1")
		if v6 {
			stride, pidOffset, timeOffset, portOffset = 176, 24, 32, 20
			ip = netip.MustParseAddr("fdfe:dcba:9876::1")
		}
		raw := make([]byte, 8+2*stride)
		binary.LittleEndian.PutUint32(raw, 2)
		for i := range 2 {
			row := raw[8+i*stride:]
			copy(row, ip.AsSlice())
			binary.BigEndian.PutUint16(row[portOffset:], 12345)
			binary.LittleEndian.PutUint32(row[pidOffset:], 100+uint32(i))
			binary.LittleEndian.PutUint64(row[timeOffset:], 1000+uint64(i))
		}
		rows := map[netip.AddrPort][]socketOwner{}
		if err := parseUDP(raw, v6, rows); err != nil {
			t.Fatal(err)
		}
		key := netip.AddrPortFrom(ip, 12345)
		if len(rows[key]) != 2 || rows[key][1].created != 1001 {
			t.Fatal(rows)
		}
		if _, err := NewOwners().udpOwner(key, rows); !errors.Is(err, platform.ErrAmbiguous) {
			t.Fatal(err)
		}
		if err := parseUDP(raw[:len(raw)-1], v6, rows); err == nil {
			t.Fatal("accepted partial UDP table")
		}
	}
}

func TestUDPGenerationOnLiveReuse(t *testing.T) {
	hosted(t)
	o := NewOwners()
	ctx := context.Background()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	key := netip.AddrPortFrom(netip.MustParseAddr("198.18.0.1"), uint16(port))
	first, err := o.UDP(ctx, key)
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	conn.Close()
	conn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	second, err := o.UDP(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if first.PID != uint32(os.Getpid()) || second.PID != first.PID || second.StartTime != first.StartTime || first.Generation == second.Generation {
		t.Fatalf("socket creation identity was reused: first=%+v second=%+v", first, second)
	}
	snapshot, err := o.Snapshot(ctx, []netip.AddrPort{key})
	if err != nil || snapshot[key].Generation != second.Generation {
		t.Fatalf("%v %v", snapshot, err)
	}
}

func TestOwnerColdBurstTiming(t *testing.T) {
	hosted(t)
	if os.Getenv("NETSWITCH_LOOKUP_GATE") != "1" {
		t.Skip("timing is measured once per architecture without race instrumentation")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var held []net.Conn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	for range 1000 {
		c, err := net.Dial("tcp4", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		server, err := listener.Accept()
		if err != nil {
			c.Close()
			t.Fatal(err)
		}
		held = append(held, c, server)
	}
	o := NewOwners()
	var mu sync.Mutex
	var durations []time.Duration
	misses := 0
	work := make(chan int, 1000)
	for i := range 1000 {
		work <- i
	}
	close(work)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var workers sync.WaitGroup
	var accepts sync.WaitGroup
	accepts.Go(func() {
		for range 1000 {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	})
	for range 32 {
		workers.Go(func() {
			for range work {
				c, err := (&net.Dialer{}).DialContext(ctx, "tcp4", listener.Addr().String())
				if err != nil {
					mu.Lock()
					misses++
					mu.Unlock()
					continue
				}
				start := time.Now()
				owner, err := o.TCP(ctx, platform.Tuple{Source: c.LocalAddr().(*net.TCPAddr).AddrPort(), Destination: c.RemoteAddr().(*net.TCPAddr).AddrPort()})
				elapsed := time.Since(start)
				mu.Lock()
				held = append(held, c)
				durations = append(durations, elapsed)
				if err != nil || owner.PID != uint32(os.Getpid()) {
					misses++
				}
				mu.Unlock()
			}
		})
	}
	workers.Wait()
	listener.Close()
	accepts.Wait()
	slices.Sort(durations)
	if len(durations) != 1000 {
		t.Fatalf("only %d/1000 cold socket lookups ran", len(durations))
	}
	p95 := durations[949]
	raw, _ := json.Marshal(o.Stats())
	t.Logf("WINDOWS OWNER GATE rows>=2000 cold=1000 found=%d p95_us=%d processors=%d cpus=%d histogram=%s", 1000-misses, p95.Microseconds(), runtime.GOMAXPROCS(0), runtime.NumCPU(), raw)
	if misses > 5 || p95 >= 5*time.Millisecond {
		t.Fatalf("owner gate: misses=%d p95=%s", misses, p95)
	}
}

func TestOwnerConcurrentSnapshots(t *testing.T) {
	hosted(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var clients, servers []net.Conn
	defer func() {
		for _, c := range append(clients, servers...) {
			c.Close()
		}
	}()
	for range 64 {
		client, err := net.Dial("tcp4", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, client)
		server, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		servers = append(servers, server)
	}
	owners := NewOwners()
	var work sync.WaitGroup
	for _, client := range clients {
		work.Go(func() {
			tuple := platform.Tuple{Source: client.LocalAddr().(*net.TCPAddr).AddrPort(), Destination: client.RemoteAddr().(*net.TCPAddr).AddrPort()}
			owner, err := owners.TCP(context.Background(), tuple)
			if err != nil || owner.PID != uint32(os.Getpid()) {
				t.Errorf("concurrent native snapshot: %+v %v", owner, err)
			}
		})
	}
	work.Wait()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := owners.tcpSnapshot(ctx, time.Time{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled snapshot returned %v", err)
	}
}

func TestUDPReadinessDoesNotConsume(t *testing.T) {
	hosted(t)
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	raw, err := server.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	s := &udpSocket{conn: server, raw: raw}
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, payload := range [][]byte{nil, []byte("keep this datagram")} {
		if _, err := client.Write(payload); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if err := s.WaitReadable(ctx); err != nil {
			cancel()
			t.Fatal(err)
		}
		if err := s.WaitReadable(ctx); err != nil {
			cancel()
			t.Fatal(err)
		}
		var b [128]byte
		n, _, err := s.ReadFrom(b[:])
		cancel()
		if err != nil || string(b[:n]) != string(payload) {
			t.Fatalf("%q %v", b[:n], err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := s.WaitReadable(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.WaitReadable(context.Background()) }()
	s.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not wake UDP readiness")
	}
}

func TestReadinessHalfCloseAndCancellation(t *testing.T) {
	hosted(t)
	pool, err := newReadiness()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := pool.close(); err != nil {
			t.Error(err)
		}
	}()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for round := range 32 {
		client, err := net.Dial("tcp4", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		server, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		c := &readySocket{blocking: client.(*net.TCPConn), pool: pool, local: client.LocalAddr(), remote: client.RemoteAddr()}
		wake := make(chan struct{}, 1)
		w, err := c.Watch(func() {
			select {
			case wake <- struct{}{}:
			default:
			}
		})
		if err != nil {
			client.Close()
			server.Close()
			t.Fatal(err)
		}
		if _, err := c.TryRead(make([]byte, 10)); !errors.Is(err, platform.ErrWouldBlock) {
			t.Fatal(err)
		}
		if err := w.Arm(true, false); err != nil {
			t.Fatal(err)
		}
		if round%2 == 0 {
			server.Write([]byte("actual reply"))
			server.(*net.TCPConn).CloseWrite()
			var got []byte
			deadline := time.After(3 * time.Second)
			for {
				select {
				case <-wake:
				case <-deadline:
					t.Fatal("readiness timeout")
				}
				var b [32]byte
				n, err := c.TryRead(b[:])
				got = append(got, b[:n]...)
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil && !errors.Is(err, platform.ErrWouldBlock) {
					t.Fatal(err)
				}
				if err := w.Arm(true, false); err != nil {
					t.Fatal(err)
				}
			}
			if string(got) != "actual reply" {
				t.Fatal(string(got))
			}
			if _, err := c.TryWrite([]byte("still writable")); err != nil {
				t.Fatal(err)
			}
			c.CloseWrite()
			reply, err := io.ReadAll(server)
			if err != nil || string(reply) != "still writable" {
				t.Fatalf("%q %v", reply, err)
			}
		}
		w.Detach() // Odd rounds cancel a genuinely pending zero-byte receive.
		c.Close()
		server.Close()
	}
}

func TestPrivateStateDirectory(t *testing.T) {
	hosted(t)
	path := filepath.Join(t.TempDir(), "private")
	f, err := StateDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	f, err = StateDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func TestStateDoesNotSalvageUntrustedRecords(t *testing.T) {
	hosted(t)
	parent := t.TempDir()
	state := filepath.Join(parent, "occupied")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "engine-journal.json"), []byte("untrusted ownership records"), 0600); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(state, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	f, err := StateDirectory(state)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := os.Stat(filepath.Join(state, "engine-journal.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("untrusted records were imported: %v", err)
	}
	moved, err := filepath.Glob(state + ".untrusted-*")
	if err != nil || len(moved) != 1 {
		t.Fatalf("%v %v", moved, err)
	}
	b, err := os.ReadFile(filepath.Join(moved[0], "engine-journal.json"))
	if err != nil || string(b) != "untrusted ownership records" {
		t.Fatalf("quarantine changed data: %q %v", b, err)
	}
}

func TestStateMovesHardLinkWithoutChangingTarget(t *testing.T) {
	hosted(t)
	parent := t.TempDir()
	victim, state := filepath.Join(parent, "victim"), filepath.Join(parent, "occupied")
	if err := os.WriteFile(victim, []byte("unchanged target"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(victim, state); err != nil {
		t.Fatal(err)
	}
	f, err := StateDirectory(state)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, err := os.ReadFile(victim)
	if err != nil || string(b) != "unchanged target" {
		t.Fatalf("%q %v", b, err)
	}
}
