//go:build windows

package winengine

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

type socketTraceHandle struct {
	stage string
	value windows.Handle
}

type socketEvidence struct {
	t               *testing.T
	local, peer     netip.AddrPort // cached BEFORE File/Watch closes the Go connection
	kind            int
	handles         []socketTraceHandle
	stages          []string
	window          []socketTraceEntry
	before          []socketTraceEntry
	thread          uintptr
	marker          windows.Handle
	failed          bool
	watchMismatch   error
	capturedHistory int
	tcp             *readySocket
	tcpPeer         *net.TCPConn
	udp             *udpSocket
}

var socketFirstFailure atomic.Bool
var udpSocketEvidence sync.Map // *udpSocket -> *socketEvidence, test lifetime only

func diagnosticHandle(t *testing.T, value interface {
	SyscallConn() (syscall.RawConn, error)
}) windows.Handle {
	t.Helper()
	raw, err := value.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var h windows.Handle
	if err := raw.Control(func(fd uintptr) { h = windows.Handle(fd) }); err != nil {
		t.Fatal(err)
	}
	// For historical identification only; never close this borrowed number.
	return h
}

func tcpSocketEvidence(t *testing.T, c *readySocket, peer *net.TCPConn) *socketEvidence {
	if !socketDiagnosticsEnabled() {
		return nil
	}
	d := &socketEvidence{t: t, tcp: c, tcpPeer: peer, kind: windows.SOCK_STREAM,
		local: c.LocalAddr().(*net.TCPAddr).AddrPort(), peer: peer.LocalAddr().(*net.TCPAddr).AddrPort()}
	d.handles = append(d.handles, socketTraceHandle{"original-Go", diagnosticHandle(t, c.blocking)},
		socketTraceHandle{"peer-Go", diagnosticHandle(t, peer)})
	return d
}

func newUDPSocketEvidence(t *testing.T, s *udpSocket, peer *net.UDPConn) *socketEvidence {
	if !socketDiagnosticsEnabled() {
		return nil
	}
	d := &socketEvidence{t: t, udp: s, kind: windows.SOCK_DGRAM,
		local: s.LocalAddr(), peer: peer.LocalAddr().(*net.UDPAddr).AddrPort()}
	d.handles = append(d.handles, socketTraceHandle{"original-Go", diagnosticHandle(t, s.conn)},
		socketTraceHandle{"peer-Go", diagnosticHandle(t, peer)})
	udpSocketEvidence.Store(s, d)
	t.Cleanup(func() {
		if t.Failed() {
			d.failure("before UDP peer cleanup", errors.New("see original assertion"))
		}
	})
	return d
}

// Surround the REAL Watch call. No replacement File(), extra socket duplicate,
// function patching, or production hook. Its private File handle cannot be read
// directly: preserve every new same-thread record, explicitly as candidates.
// The staged diagnostic fixture below supplies exact File attribution too.
func (d *socketEvidence) beforeWatch() {
	if d == nil {
		return
	}
	d.t.Helper()
	runtime.LockOSThread()
	d.thread = uintptr(windows.GetCurrentThreadId())
	marker, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		runtime.UnlockOSThread()
		d.t.Fatal(err)
	}
	d.marker = marker
	d.before, err = querySocketTrace(0)
	if err != nil {
		windows.CloseHandle(marker)
		d.marker = 0
		runtime.UnlockOSThread()
		d.t.Fatal(err)
	}
}

func (d *socketEvidence) afterWatch(owner winhandle.Owner, watchErr error) {
	if d == nil {
		return
	}
	d.t.Helper()
	defer runtime.UnlockOSThread()
	defer func() {
		err := windows.CloseHandle(d.marker)
		d.marker = 0
		if err != nil {
			d.t.Errorf("trace marker close: %v", err)
		}
	}()
	if !owner.IsZero() {
		d.handles = append(d.handles, socketTraceHandle{"native-after-Watch", owner.Handle("test trace native identity")})
	}
	after, err := querySocketTrace(0)
	if err != nil {
		d.t.Fatal(err)
	}
	if !traceHas(after, d.marker, d.thread, 1) {
		d.t.Fatal("Watch trace window lost its live marker OPEN; evidence may have wrapped")
	}
	d.t.Logf("HTRACE Watch window before=%d after=%d full=%t; multiset deltas are ambiguous after eviction",
		len(d.before), len(after), len(d.before) == socketTraceSlots || len(after) == socketTraceSlots)
	for _, e := range socketTraceDelta(d.before, after) {
		if e.TID == d.thread && e.Handle != d.marker {
			d.window = append(d.window, e)
			known := false
			for _, h := range d.handles {
				known = known || h.value == e.Handle
			}
			if !known && e.Type == 1 {
				d.handles = append(d.handles, socketTraceHandle{"Watch-temporary/File-candidate", e.Handle})
			}
		}
	}
	d.before = nil
	if watchErr != nil {
		d.failure("Watch returned error", watchErr)
		return // caller keeps its original failing assertion
	}
	d.watchMismatch = d.observe("Watch completed; both Go descriptors closed", owner.Handle("test trace Watch type"))
	if d.watchMismatch != nil {
		// Preserve the first state without sending diagnostic payload before
		// the original read/EOF/payload assertions have had a chance to run.
		d.t.Logf("SOCKET WATCH MISMATCH %v; original assertions continue", d.watchMismatch)
		d.trace("Watch-mismatch-before-original-I/O")
		d.tables("Watch-mismatch-before-original-I/O")
	}
}

func (d *socketEvidence) expect(stage string, h windows.Handle) {
	if d == nil {
		return
	}
	d.t.Helper()
	if err := d.observe(stage, h); err != nil {
		d.failure(stage, err)
		d.t.Fatal(err)
	}
}

func (d *socketEvidence) observe(stage string, h windows.Handle) error {
	if d == nil {
		return nil
	}
	d.t.Helper()
	kind, kindErr := windows.GetsockoptInt(h, windows.SOL_SOCKET, 0x1008)
	local, localErr := windows.Getsockname(h)
	peer, peerErr := windows.Getpeername(h)
	d.stages = append(d.stages, fmt.Sprintf("%s handle=%#x type=%d/%v local=%v/%v peer=%v/%v",
		stage, h, kind, kindErr, diagnosticAddress(local), localErr, diagnosticAddress(peer), peerErr))
	bad := kindErr != nil || kind != d.kind || localErr != nil || diagnosticAddress(local) != d.local
	if d.kind == windows.SOCK_STREAM {
		bad = bad || peerErr != nil || diagnosticAddress(peer) != d.peer
	}
	if bad {
		return fmt.Errorf("%s: type=%d/%v local=%v/%v peer=%v/%v", stage,
			kind, kindErr, diagnosticAddress(local), localErr, diagnosticAddress(peer), peerErr)
	}
	return nil
}

func (d *socketEvidence) assertWatchIdentity() {
	if d != nil && d.watchMismatch != nil {
		d.failure("Watch identity mismatch after original assertions", d.watchMismatch)
		d.t.Fatal(d.watchMismatch)
	}
}

func diagnosticAddress(sa windows.Sockaddr) netip.AddrPort {
	switch a := sa.(type) {
	case *windows.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(a.Addr), uint16(a.Port))
	case *windows.SockaddrInet6:
		return netip.AddrPortFrom(netip.AddrFrom16(a.Addr), uint16(a.Port))
	}
	return netip.AddrPort{}
}

func (d *socketEvidence) trace(stage string) int {
	entries, err := querySocketTrace(0) // freeze history BEFORE table/payload probes
	if err != nil {
		d.t.Logf("HTRACE stage=%s query-error=%v", stage, err)
		return 0
	}
	d.t.Logf("HTRACE SNAPSHOT stage=%s total=%d capacity=%d full=%t; a full ring may have evicted earlier generations",
		stage, len(entries), socketTraceSlots, len(entries) == socketTraceSlots)
	captured := 0
	for _, h := range d.handles {
		var matches []socketTraceEntry
		for _, e := range entries {
			if e.Handle == h.value {
				matches = append(matches, e)
			}
		}
		logSocketTrace(d.t, stage+"/"+h.stage, matches)
		captured += len(matches)
	}
	return captured
}

func (d *socketEvidence) failure(stage string, cause error) {
	if d == nil || d.failed {
		return
	}
	d.t.Helper()
	if !socketFirstFailure.CompareAndSwap(false, true) {
		d.t.Logf("SOCKET FAILURE stage=%s error=%v; first full process capture already emitted", stage, cause)
		return
	}
	d.failed = true
	// A tripwire can fire before Watch publishes its native number. Its
	// saved number is useful for history only; it never authorizes socket I/O.
	const violationPrefix = "WINDOWS HANDLE OWNERSHIP VIOLATION "
	if cause != nil {
		message := cause.Error()
		if index := strings.Index(message, violationPrefix); index >= 0 {
			var violation struct {
				Handle uint64 `json:"handle"`
			}
			if json.Unmarshal([]byte(message[index+len(violationPrefix):]), &violation) == nil {
				d.handles = append(d.handles, socketTraceHandle{"tripwire-historical-value", windows.Handle(violation.Handle)})
			}
		}
	}
	var owner winhandle.Owner
	closed := false
	if d.tcp != nil {
		owner, closed = d.tcp.handle, d.tcp.closed
	} else if d.udp != nil {
		owner, closed = d.udp.handle, d.udp.closed
	}
	d.t.Logf("SOCKET FAILURE stage=%s error=%v original-app=%s original-peer=%s expected-type=%d pid=%d already-closed=%t BEFORE FAILURE CLEANUP",
		stage, cause, d.local, d.peer, d.kind, os.Getpid(), closed)
	d.capturedHistory = d.trace("first-failure/" + stage)
	logSocketTrace(d.t, "real-Watch-window/File-candidates", d.window)
	for _, s := range d.stages {
		d.t.Logf("SOCKET STAGE %s", s)
	}
	d.tables("before-payload")
	var h windows.Handle
	nativeLive := false
	if !owner.IsZero() && !closed {
		// The tripwire itself may have raised the original panic. Capture
		// saved numeric histories first, then refuse all I/O on an ended owner.
		func() {
			defer func() {
				if value := recover(); value != nil {
					d.t.Logf("SOCKET native probe skipped after ownership failure: %v", value)
				}
			}()
			h = owner.Handle("test first-failure socket state")
			nativeLive = true
		}()
		closed = !nativeLive
	}
	if nativeLive {
		local, le := windows.Getsockname(h)
		peer, pe := windows.Getpeername(h)
		kind, ke := windows.GetsockoptInt(h, windows.SOL_SOCKET, 0x1008)
		// SO_ERROR is read only here, after the primary history/table snapshot;
		// Winsock may clear it. Never interrogate the released Go/File numbers.
		se, see := windows.GetsockoptInt(h, windows.SOL_SOCKET, 0x1007)
		d.t.Logf("SOCKET NATIVE handle=%#x local=%v/%v peer=%v/%v type=%d/%v SO_ERROR=%d/%v",
			h, diagnosticAddress(local), le, diagnosticAddress(peer), pe, kind, ke, se, see)
	}
	if closed {
		d.t.Log("SOCKET POSTERROR unavailable: the owner is closed or its generation ended; no stale I/O attempted")
	} else if d.tcp != nil {
		payload := []byte("socket-diagnostic-after-error")
		var n int
		var err error
		path := "native"
		if d.tcp.blocking != nil {
			path = "original Go socket (native handoff incomplete)"
			d.tcp.blocking.SetWriteDeadline(time.Now().Add(time.Second))
			n, err = d.tcp.blocking.Write(payload)
		} else {
			n, err = d.tcp.TryWrite(payload) // one attempt, never a retry to pass
		}
		d.t.Logf("SOCKET POSTERROR TCP path=%s send=%d/%d error=%v payload=%q", path, n, len(payload), err, payload)
		deadlineErr := d.tcpPeer.SetReadDeadline(time.Now().Add(time.Second))
		// Bounded even if a corrupted endpoint unexpectedly receives traffic.
		got, readErr := io.ReadAll(io.LimitReader(d.tcpPeer, 4096))
		d.t.Logf("SOCKET POSTERROR TCP peer=%s observed=%q read-error=%v deadline-error=%v BEFORE CLEANUP (nil read-error means FIN only when len<4096)",
			d.peer, got, readErr, deadlineErr)
	} else if d.udp != nil {
		d.udpPayloadProbe()
	}
	d.tables("after-payload-before-cleanup")
	d.trace("after-payload-before-cleanup")
	socketTraceModules(d.t)
	d.t.Log("SOCKET EVIDENCE: retained peer state/absent FIN does not rule out reuse; a leaked duplicate could retain the original connection. Missing trace records do not prove absence of closes.")
}

func (d *socketEvidence) udpPayloadProbe() {
	network, ip := "udp4", net.IPv4(127, 0, 0, 1)
	if d.local.Addr().Is6() {
		network, ip = "udp6", net.IPv6loopback
	}
	receiver, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
	if err != nil {
		d.t.Logf("SOCKET POSTERROR UDP separate receiver creation: %v", err)
		return
	}
	defer receiver.Close()
	payload := []byte("socket-diagnostic-after-error")
	destination := receiver.LocalAddr().(*net.UDPAddr).AddrPort()
	var n int
	path := "native"
	if d.udp.conn != nil {
		path = "original Go socket (native handoff incomplete)"
		d.udp.conn.SetWriteDeadline(time.Now().Add(time.Second))
		n, err = d.udp.conn.WriteToUDPAddrPort(payload, destination)
	} else {
		// Independent documented sendto, without TryWriteTo's fragmentation
		// setsockopt, so a failed option cannot hide whether sending works.
		var to windows.Sockaddr = &windows.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}, Port: int(destination.Port())}
		if destination.Addr().Is6() {
			to = &windows.SockaddrInet6{Addr: destination.Addr().As16(), Port: int(destination.Port())}
		}
		err = windows.Sendto(d.udp.handle.Handle("test post-error UDP sendto"), payload, 0, to)
		if err == nil {
			n = len(payload) // x/sys sendto exposes only an error; UDP is atomic
		}
	}
	d.t.Logf("SOCKET POSTERROR UDP path=%s send=%d/%d destination=%s error=%v payload=%q", path, n, len(payload), destination, err, payload)
	deadlineErr := receiver.SetReadDeadline(time.Now().Add(time.Second))
	var b [256]byte
	n, source, readErr := receiver.ReadFromUDPAddrPort(b[:])
	d.t.Logf("SOCKET POSTERROR UDP separate receiver source=%s expected-original=%s payload=%q read-error=%v deadline-error=%v BEFORE CLEANUP",
		source, d.local, b[:n], readErr, deadlineErr)
}

func (d *socketEvidence) closeTCP() {
	if d == nil {
		return
	}
	panicked := recover()
	if panicked != nil {
		defer func() { panic(panicked) }()
		d.failure("panic before deferred TCP close", fmt.Errorf("%v", panicked))
	}
	if d.t.Failed() {
		d.failure("test failed before deferred TCP close", errors.New("see original assertion"))
	}
	err := d.tcp.Close()
	if d.failed || err != nil {
		d.t.Logf("SOCKET CLEANUP TCP Close result=%v", err)
		d.trace("after-explicit-TCP-close")
		d.tables("after-explicit-TCP-close")
	}
	if err != nil {
		d.t.Errorf("diagnostic TCP close: %v", err)
	}
}

func closeUDPEvidence(t *testing.T, s *udpSocket) error {
	value, ok := udpSocketEvidence.LoadAndDelete(s)
	if !ok {
		return s.Close()
	}
	d := value.(*socketEvidence)
	if t.Failed() {
		d.failure("test failed before UDP cleanup", errors.New("see original assertion"))
	}
	err := s.Close()
	if d.failed || err != nil {
		t.Logf("SOCKET CLEANUP UDP Close result=%v", err)
		d.trace("after-explicit-UDP-close")
		d.tables("after-explicit-UDP-close")
	}
	return err
}

// Own decoder of documented OWNER_PID rows, independent of Owners/cache.
// SDK layouts checked in Microsoft's win32metadata RecompiledIdlHeaders/shared
// tcpmib.h and udpmib.h: TCP4=24 TCP6=56 UDP4=12 UDP6=28, DWORD header=4.
// https://learn.microsoft.com/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable
// https://learn.microsoft.com/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable
type diagnosticTableRow struct {
	local, remote netip.AddrPort
	pid, state    uint32
	localScope    uint32
	remoteScope   uint32
}

func socketDiagnosticTable(tcp, v6 bool) ([]diagnosticTableRow, error) {
	proc, class, stride := udpTable, uintptr(1), 12 // UDP_TABLE_OWNER_PID
	if tcp {
		proc, class, stride = tcpTable, 5, 24 // TCP_TABLE_OWNER_PID_ALL
	}
	af := uintptr(windows.AF_INET)
	if v6 {
		af = windows.AF_INET6
		stride = 28
		if tcp {
			stride = 56
		}
	}
	size := uint32(64 * 1024)
	for range 3 { // only buffer sizing may retry, never a socket operation
		if size < 4 || size > 16*1024*1024 {
			return nil, fmt.Errorf("table size outside diagnostic bound: %d", size)
		}
		words := make([]uint64, (int(size)+7)/8)
		allocated := len(words) * 8
		size = uint32(allocated)
		code, _, _ := proc.Call(uintptr(unsafe.Pointer(&words[0])), uintptr(unsafe.Pointer(&size)), 0, af, class, 0)
		if code == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if code != 0 {
			return nil, syscall.Errno(code)
		}
		if size < 4 || int(size) > allocated {
			return nil, fmt.Errorf("invalid table return size=%d allocated=%d", size, allocated)
		}
		b := unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), int(size))
		count := binary.LittleEndian.Uint32(b)
		if uint64(count)*uint64(stride)+4 > uint64(len(b)) {
			return nil, fmt.Errorf("table row count=%d stride=%d size=%d", count, stride, len(b))
		}
		rows := make([]diagnosticTableRow, 0, count)
		for i := range int(count) {
			raw := b[4+i*stride : 4+(i+1)*stride]
			r := diagnosticTableRow{}
			addr := func(offset, port int) netip.AddrPort {
				ip := netip.AddrFrom4([4]byte(raw[offset : offset+4]))
				if v6 {
					ip = netip.AddrFrom16([16]byte(raw[offset : offset+16]))
				}
				return netip.AddrPortFrom(ip, binary.BigEndian.Uint16(raw[port:port+2]))
			}
			if v6 {
				r.local, r.localScope = addr(0, 20), binary.LittleEndian.Uint32(raw[16:20])
				if tcp {
					r.remote, r.remoteScope = addr(24, 44), binary.LittleEndian.Uint32(raw[40:44])
					r.state, r.pid = binary.LittleEndian.Uint32(raw[48:52]), binary.LittleEndian.Uint32(raw[52:56])
				} else {
					r.pid = binary.LittleEndian.Uint32(raw[24:28])
				}
			} else if tcp {
				r.state, r.pid = binary.LittleEndian.Uint32(raw[:4]), binary.LittleEndian.Uint32(raw[20:24])
				r.local, r.remote = addr(4, 8), addr(12, 16)
			} else {
				r.local, r.pid = addr(0, 4), binary.LittleEndian.Uint32(raw[8:12])
			}
			rows = append(rows, r)
		}
		return rows, nil
	}
	return nil, errors.New("table grew during three bounded sizing attempts")
}

func (d *socketEvidence) tables(stage string) {
	for _, tcp := range []bool{true, false} {
		for _, v6 := range []bool{false, true} {
			rows, err := socketDiagnosticTable(tcp, v6)
			matched := 0
			for _, r := range rows {
				if r.local != d.local && r.local != d.peer && r.remote != d.local && r.remote != d.peer {
					continue
				}
				matched++
				d.t.Logf("SOCKET TABLE stage=%s tcp=%t ipv6=%t local=%s remote=%s pid=%d state=%d scope-raw-le=%#x/%#x",
					stage, tcp, v6, r.local, r.remote, r.pid, r.state, r.localScope, r.remoteScope)
			}
			d.t.Logf("SOCKET TABLE stage=%s tcp=%t ipv6=%t total=%d matching-original-tuples=%d error=%v", stage, tcp, v6, len(rows), matched, err)
		}
	}
}

func (d *socketEvidence) proveTable() {
	d.t.Helper()
	rows, err := socketDiagnosticTable(d.kind == windows.SOCK_STREAM, d.local.Addr().Is6())
	if err != nil {
		d.t.Fatal(err)
	}
	for _, r := range rows {
		if r.local == d.local && r.pid == uint32(os.Getpid()) && (d.kind != windows.SOCK_STREAM || r.remote == d.peer && r.state == 5) {
			d.t.Logf("SOCKET TABLE CONTROL PASS app=%s peer=%s pid=%d state=%d", r.local, r.remote, r.pid, r.state)
			return
		}
	}
	d.failure("native table control", errors.New("live tuple/PID missing"))
	d.t.Fatal("native table control did not find the known live tuple/PID")
}
