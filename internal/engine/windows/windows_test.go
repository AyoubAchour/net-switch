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
	rows := tcpIndex{}
	if err := parseTCP(raw, false, &rows); err != nil {
		t.Fatal(err)
	}
	key := platform.Tuple{Source: netip.MustParseAddrPort("198.18.0.1:40000"), Destination: netip.MustParseAddrPort("1.1.1.1:443")}
	if len(rows.v4)+len(rows.v6) != 1 || rows.find(key) != (tcpCandidates{pid: 123, count: 1}) {
		t.Fatal(rows)
	}
	if err := parseTCP(raw[:len(raw)-1], false, &rows); err == nil {
		t.Fatal("accepted partial TCP table")
	}
	copy(raw[4+24:], raw[4:4+24])
	binary.LittleEndian.PutUint32(raw[4+24+20:], 456)
	rows = tcpIndex{}
	if err := parseTCP(raw, false, &rows); err != nil || len(rows.v4)+len(rows.v6) != 1 || rows.find(key).count != 2 {
		t.Fatalf("lost ambiguous exact tuple: %v %v", rows, err)
	}
}

func TestTCPMappedListenerWithUnspecifiedPeer(t *testing.T) {
	raw := make([]byte, 4+56)
	binary.LittleEndian.PutUint32(raw, 1)
	source := netip.MustParseAddr("::ffff:127.0.0.1").As16()
	copy(raw[4:20], source[:])
	binary.BigEndian.PutUint16(raw[4+20:], 40000)
	binary.LittleEndian.PutUint32(raw[4+48:], 2) // LISTEN, with an unspecified IPv6 peer.
	binary.LittleEndian.PutUint32(raw[4+52:], 123)
	var rows tcpIndex
	if err := parseTCP(raw, true, &rows); err != nil {
		t.Fatal(err)
	}
	key := platform.Tuple{Source: netip.MustParseAddrPort("127.0.0.1:40000"), Destination: netip.MustParseAddrPort("[::]:0")}
	if rows.find(key) != (tcpCandidates{pid: 123, count: 1}) {
		t.Fatal("lost the valid mapped listener row", rows)
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
	if first.PID != uint32(os.Getpid()) || second.PID != first.PID || second.StartTime != first.StartTime ||
		first.Generation == "" || second.Generation == "" {
		t.Fatalf("socket owner identity was lost: first=%+v second=%+v", first, second)
	}
	// Known Windows limitation, approved after a real OWNER_MODULE collision:
	// same-process immediate reuse may retain the creation timestamp. Cross-
	// process identity, explicit close selectors and lifetime bounds stay hard.
	t.Logf("KNOWN WINDOWS LIMITATION same_process_immediate_udp_reuse collision=%t old_unique_timestamp_check_would_pass=%t first=%s second=%s",
		first.Generation == second.Generation, first.Generation != second.Generation, first.Generation, second.Generation)
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
	// Winsock's SOMAXCONN backlog is only several hundred. A single listener
	// refused new native sockets before the owner lookup even ran (457 created,
	// 282 accepted on ARM). Eight peers keep each pending queue below 125 while
	// retaining the same 1,000 cold sockets, 32 workers and attribution limit.
	var listeners []net.Listener
	for range 8 {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		defer listener.Close()
	}
	listener := listeners[0]
	var held []net.Conn
	defer func() {
		for _, c := range held {
			c.(*net.TCPConn).SetLinger(0)
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
	rowsBefore, timeWaitBefore := nativeTCPRowCounts(t)
	o := NewOwners()
	counter, frequency := lookupPerformanceClock(t)
	var mu sync.Mutex
	var durations, oldDurations []time.Duration
	var dialErrors []string
	var acceptError error
	accepted := 0
	acceptedAll := make(chan struct{})
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
	for _, listener := range listeners {
		accepts.Go(func() {
			for {
				c, err := listener.Accept()
				if err != nil {
					if !errors.Is(err, net.ErrClosed) {
						mu.Lock()
						acceptError = err
						mu.Unlock()
					}
					return
				}
				mu.Lock()
				accepted++
				held = append(held, c)
				if accepted == 1000 {
					close(acceptedAll)
				}
				mu.Unlock()
			}
		})
	}
	for range 32 {
		workers.Go(func() {
			for index := range work {
				c, err := (&net.Dialer{}).DialContext(ctx, "tcp4", listeners[index%len(listeners)].Addr().String())
				if err != nil {
					mu.Lock()
					misses++
					if len(dialErrors) < 8 {
						dialErrors = append(dialErrors, err.Error())
					}
					mu.Unlock()
					continue
				}
				start := time.Now()
				preciseStart := counter()
				owner, err := o.TCP(ctx, platform.Tuple{Source: c.LocalAddr().(*net.TCPAddr).AddrPort(), Destination: c.RemoteAddr().(*net.TCPAddr).AddrPort()})
				preciseElapsed := time.Duration((counter() - preciseStart) * int64(time.Second) / frequency)
				elapsed := time.Since(start)
				mu.Lock()
				held = append(held, c)
				durations = append(durations, preciseElapsed)
				oldDurations = append(oldDurations, elapsed)
				if err != nil || owner.PID != uint32(os.Getpid()) {
					misses++
				}
				mu.Unlock()
			}
		})
	}
	workers.Wait()
	if len(durations) == 1000 {
		select {
		case <-acceptedAll:
		case <-ctx.Done():
			t.Error("native listener did not accept all established burst sockets")
		}
	}
	for _, listener := range listeners {
		listener.Close()
	}
	accepts.Wait()
	slices.Sort(durations)
	slices.Sort(oldDurations)
	if len(durations) != 1000 {
		t.Fatalf("only %d/1000 cold socket lookups ran; accepted=%d accept_error=%v; dial failures: %v", len(durations), accepted, acceptError, dialErrors)
	}
	p95 := durations[949]
	oldP95 := oldDurations[949]
	rowsAfter, timeWaitAfter := nativeTCPRowCounts(t)
	raw, _ := json.Marshal(o.Stats())
	t.Logf("WINDOWS OWNER BURST cold=1000 found=%d peers=%d accepted=%d p95_us=%d old_go_p95_us=%d raw_rows_before=%d raw_rows_after=%d timewait_before=%d timewait_after=%d processors=%d cpus=%d old_combined_gate_would_pass=%t histogram=%s", 1000-misses, len(listeners), accepted, p95.Microseconds(), oldP95.Microseconds(), rowsBefore, rowsAfter, timeWaitBefore, timeWaitAfter, runtime.GOMAXPROCS(0), runtime.NumCPU(), misses <= 5 && oldP95 < 5*time.Millisecond, raw)
	if misses > 5 {
		t.Fatalf("owner burst gate: found=%d/1000 (requires at least 995), p95=%s", 1000-misses, p95)
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
			c.(*net.TCPConn).SetLinger(0)
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
	if _, err := owners.tcpSnapshot(ctx, 0, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled snapshot returned %v", err)
	}
}

func TestOwnerIPv6AndMappedIPv4(t *testing.T) {
	hosted(t)
	for _, scenario := range []struct{ network, address, destination string }{
		{"tcp4", "127.0.0.1:0", "::ffff:127.0.0.1"},
		{"tcp6", "[::1]:0", "::1"},
	} {
		t.Run(scenario.network, func(t *testing.T) {
			listener, err := net.Listen(scenario.network, scenario.address)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			socket, err := windows.Socket(windows.AF_INET6, windows.SOCK_STREAM, windows.IPPROTO_TCP)
			if err != nil {
				t.Fatal(err)
			}
			defer windows.Closesocket(socket)
			if err := windows.SetsockoptInt(socket, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY, 0); err != nil {
				t.Fatal(err)
			}
			if err := windows.SetsockoptLinger(socket, windows.SOL_SOCKET, windows.SO_LINGER, &windows.Linger{Onoff: 1}); err != nil {
				t.Fatal(err)
			}
			if err := windows.Bind(socket, &windows.SockaddrInet6{}); err != nil {
				t.Fatal(err)
			}
			destination := netip.MustParseAddr(scenario.destination).As16()
			if err := windows.Connect(socket, &windows.SockaddrInet6{Addr: destination, Port: listener.Addr().(*net.TCPAddr).Port}); err != nil {
				t.Fatal(err)
			}
			peer, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			peer.(*net.TCPConn).SetLinger(0)
			tuple := platform.Tuple{Source: peer.RemoteAddr().(*net.TCPAddr).AddrPort(), Destination: peer.LocalAddr().(*net.TCPAddr).AddrPort()}
			owners := NewOwners()
			owner, err := owners.TCP(context.Background(), tuple)
			if err != nil || owner.PID != uint32(os.Getpid()) {
				t.Fatalf("IPv6 socket attribution: %+v %v", owner, err)
			}
			t.Logf("native IPv6 socket to %s: sampled families=%v", scenario.destination, owners.Stats().TCPFamiliesSampled)
		})
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
	for round := range 256 {
		client, err := net.Dial("tcp4", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		server, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		c := &readySocket{blocking: client.(*net.TCPConn), pool: pool, local: client.LocalAddr(), remote: client.RemoteAddr()}
		defer c.Close()
		defer server.Close()
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
			if err := server.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatalf("round %d: peer half-close: %v", round, err)
			}
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
			remaining := []byte("still writable")
			for len(remaining) != 0 {
				n, err := c.TryWrite(remaining)
				remaining = remaining[n:]
				if err != nil && !errors.Is(err, platform.ErrWouldBlock) {
					t.Fatalf("round %d: reverse write: %v", round, err)
				}
				if len(remaining) != 0 {
					if err := w.Arm(false, true); err != nil {
						t.Fatal(err)
					}
					select {
					case <-wake:
					case <-deadline:
						t.Fatalf("round %d: reverse write readiness timeout", round)
					}
				}
			}
			if err := c.CloseWrite(); err != nil {
				// Keep the original failure, but observe the actual peer before
				// deferred close can turn a missing FIN into an apparent EOF.
				local, localErr := windows.Getsockname(c.handle)
				peer, peerErr := windows.Getpeername(c.handle)
				socketError, socketErr := windows.GetsockoptInt(c.handle, windows.SOL_SOCKET, 0x1007) // SO_ERROR (Winsock).
				server.SetReadDeadline(time.Now().Add(time.Second))
				reply, readErr := io.ReadAll(server)
				t.Fatalf("round %d: native half-close: %v; descriptor=%d local=%+v/%v peer=%+v/%v SO_ERROR=%d/%v; before cleanup peer received %q read=%v",
					round, err, c.handle, local, localErr, peer, peerErr, socketError, socketErr, reply, readErr)
			}
			if err := server.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			reply, err := io.ReadAll(server)
			if err != nil || string(reply) != "still writable" {
				t.Fatalf("round %d: native half-close returned success, peer received %q: %v", round, reply, err)
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

func TestStateDirectoryHandleExcludesReplacement(t *testing.T) {
	hosted(t)
	path := filepath.Join(t.TempDir(), "held")
	directory, err := StateDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	ptr, _ := windows.UTF16PtrFromString(path)
	openDelete := func() error {
		handle, err := windows.CreateFile(ptr, windows.DELETE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err == nil {
			windows.CloseHandle(handle)
		}
		return err
	}
	heldError := openDelete()
	directory.Close()
	releasedError := openDelete()
	t.Logf("state-directory DELETE handle while held=%v after close=%v", heldError, releasedError)
	if !errors.Is(heldError, windows.ERROR_SHARING_VIOLATION) || releasedError != nil {
		t.Fatalf("the lifetime handle did not enforce replacement exclusion: held=%v released=%v", heldError, releasedError)
	}
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
