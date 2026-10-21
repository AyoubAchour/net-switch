//go:build windows

package winengine

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"golang.org/x/sys/windows"
)

// 32 rounds x four families = 128 transfers per variant. No repetition until
// green, no background unbounded allocator, no TUN, routes, firewall or service.
// The existing tests exercise the unchanged Watch methods. This separate
// fixture exposes exact original/File/native identities at each transfer stage
// using the SAME transfer/readiness primitives and source-close order as Watch.
// Its instrumentation changes timing, so success is not a root-cause fix.
func TestSocketHandleTraceChurn(t *testing.T) {
	if !startSocketDiagnostics(t) {
		t.Skip("opt in with NETSWITCH_SOCKET_DIAGNOSTICS=1 on hosted Windows")
	}
	for _, variant := range []string{"control", "GoTCP", "GoUDP"} {
		t.Run(variant, func(t *testing.T) {
			for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
				t.Run(network, func(t *testing.T) {
					for round := range 32 {
						if !t.Run(fmt.Sprintf("round-%03d", round), func(t *testing.T) {
							runSocketTraceRound(t, network, variant, round == 0)
						}) {
							return // retain FIRST failure, don't grind through 31 more
						}
					}
				})
				if t.Failed() {
					return
				}
			}
		})
		if t.Failed() {
			return
		}
	}
}

func runSocketTraceRound(t *testing.T, network, variant string, control bool) {
	t.Helper()
	ip := net.IPv4(127, 0, 0, 1)
	if network[len(network)-1] == '6' {
		ip = net.IPv6loopback
	}
	wake := make(chan struct{}, 1)
	onWake := func() {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
	var d *socketEvidence
	var conn interface {
		File() (*os.File, error)
		Close() error
	}
	var peerUDP *net.UDPConn
	if network[:3] == "tcp" {
		pool, err := newReadiness()
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := pool.close(); err != nil {
				t.Error(err)
			}
		}()
		listener, err := net.ListenTCP(network, &net.TCPAddr{IP: ip})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		client, err := net.DialTCP(network, nil, listener.Addr().(*net.TCPAddr))
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		peer, err := listener.AcceptTCP()
		if err != nil {
			t.Fatal(err)
		}
		defer peer.Close()
		c := &readySocket{blocking: client, pool: pool, local: client.LocalAddr(), remote: client.RemoteAddr()}
		d = tcpSocketEvidence(t, c, peer)
		defer d.closeTCP() // before peer and pool close, including t.Fatal paths
		c.goOwner, err = ownGoDescriptor(client, "diagnostic staged TCP original")
		if err != nil {
			t.Fatal(err)
		}
		conn = client
	} else {
		s, peer := nativeUDPPair(t, network)
		peerUDP = peer
		value, _ := udpSocketEvidence.Load(s)
		d = value.(*socketEvidence)
		var err error
		s.goOwner, err = ownGoDescriptor(s.conn, "diagnostic staged UDP original")
		if err != nil {
			t.Fatal(err)
		}
		conn = s.conn
	}
	check := func(stage string, err error) {
		t.Helper()
		if err != nil {
			d.failure(stage, err)
			t.Fatalf("descriptor stage=%s: %v", stage, err)
		}
	}
	d.expect("original Go socket before File", d.handles[0].value)
	if control {
		d.proveTable()
	}
	file, err := conn.File()
	check("Go File creation", err)
	defer file.Close() // Go Close is idempotent, no raw stale-handle close
	fileOwner, err := ownGoDescriptor(file, "diagnostic staged File")
	check("File ownership", err)
	fileClosed := false
	defer func() {
		if !fileClosed {
			err := fileOwner.CloseGo("diagnostic staged File failure cleanup", file.Close)
			t.Logf("SOCKET CLEANUP File Close result=%v", err)
		}
	}()
	fileHandle := fileOwner.Handle("diagnostic exact File identity")
	d.handles = append(d.handles, socketTraceHandle{"exact-File", fileHandle})
	d.expect("File created; original Go still open", fileHandle)
	h, err := duplicateForReadiness(file, fileOwner)
	check("duplicateForReadiness", err)
	native := h.Handle("diagnostic exact native identity")
	d.handles = append(d.handles, socketTraceHandle{"exact-native", native})
	installed := false
	var watch platform.Readiness
	defer func() {
		if !installed {
			if watch != nil {
				watch.Detach()
			}
			if d.udp != nil {
				// Until source Close succeeds, the fixture owns the native
				// duplicate and the wrapper still owns the Go connection.
				// Restore that branch before the wrapper's cleanup runs.
				d.udp.mu.Lock()
				d.udp.watch = nil
				d.udp.mu.Unlock()
			}
			err := h.SocketClose("diagnostic native before-install cleanup")
			t.Logf("SOCKET CLEANUP uninstalled native Close result=%v", err)
		}
	}()
	d.expect("native duplicate; both Go descriptors open", native)
	if d.tcp != nil {
		w, err := d.tcp.pool.watch(h, d.local.Port(), onWake)
		check("native TCP readiness registration", err)
		d.tcp.handle, d.tcp.watch, watch = h, w, w
	} else {
		w, err := d.udp.pool.watch(h, onWake)
		check("native UDP readiness registration", err)
		d.udp.handle, d.udp.watch, watch = h, w, w
	}
	// The fixture owns all failure cleanup until the source Go descriptor has
	// been released; Close on the socket wrapper still follows its Go branch.
	d.expect("readiness registered; both Go descriptors open", native)
	var sourceBefore []socketTraceEntry
	if control {
		sourceBefore, err = querySocketTrace(d.handles[0].value)
		check("source close control baseline", err)
	}
	if d.tcp != nil {
		err = d.tcp.goOwner.CloseGo("diagnostic staged TCP Go close", conn.Close)
		d.tcp.blocking = nil
	} else {
		err = d.udp.goOwner.CloseGo("diagnostic staged UDP Go close", conn.Close)
		d.udp.conn, d.udp.raw = nil, nil
	}
	installed = true // wrapper Close now detaches readiness and closes native
	check("original Go Close", err)
	if control {
		d.proveClose("original-Go", d.handles[0].value, sourceBefore)
	}
	d.expect("original Go closed; File still open", native)
	var fileBefore []socketTraceEntry
	if control {
		fileBefore, err = querySocketTrace(fileHandle)
		check("File close control baseline", err)
	}
	err = fileOwner.CloseGo("diagnostic staged File close", file.Close)
	fileClosed = true
	check("File Close", err)
	if control {
		d.proveClose("exact-File", fileHandle, fileBefore)
	}
	d.expect("both Go descriptors closed", native)
	if variant != "control" {
		// Allocate a Go-owned socket AFTER source closes and retain it while
		// probing native. This exposes reuse without DuplicateHandle, keeping
		// any surprising new owner alive until after the failure snapshot.
		closeChurn := d.goChurn(variant, network[len(network)-1])
		defer closeChurn()
	}
	runtime.GC()
	d.expect("after Go churn and forced GC", native)
	if d.tcp != nil {
		peer := d.tcpPeer
		check("peer write deadline", peer.SetWriteDeadline(time.Now().Add(time.Second)))
		_, err := peer.Write([]byte("actual reply"))
		check("peer reply", err)
		check("peer half-close", peer.CloseWrite())
		var got []byte
		deadline := time.NewTimer(2 * time.Second)
		defer deadline.Stop()
		for {
			var b [64]byte
			n, err := d.tcp.TryRead(b[:])
			got = append(got, b[:n]...)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil && !errors.Is(err, platform.ErrWouldBlock) {
				check("TCP TryRead after transfer", err)
			}
			if len(got) > 64 {
				check("TCP unexpected payload growth", errors.New("more than 64 bytes"))
			}
			check("TCP read Arm", watch.Arm(true, false))
			select {
			case <-wake:
			case <-deadline.C:
				check("TCP payload/EOF wait", errors.New("two-second deadline"))
			}
		}
		if string(got) != "actual reply" {
			check("TCP exact peer reply", fmt.Errorf("got %q", got))
		}
		n, err := d.tcp.TryWrite([]byte("still writable"))
		check("TCP reverse TryWrite", err)
		if n != len("still writable") {
			check("TCP reverse length", fmt.Errorf("got %d", n))
		}
		check("TCP CloseWrite after peer EOF", d.tcp.CloseWrite())
		check("TCP peer read deadline", peer.SetReadDeadline(time.Now().Add(time.Second)))
		got, err = io.ReadAll(io.LimitReader(peer, 4096))
		check("TCP peer FIN", err)
		if string(got) != "still writable" {
			check("TCP reverse payload", fmt.Errorf("got %q", got))
		}
	} else {
		payload := bytes.Repeat([]byte{0x3b, 0xc1, 0x97}, 4000)
		_, err := peerUDP.WriteToUDPAddrPort(payload, d.local)
		check("UDP peer send", err)
		check("UDP read Arm", watch.Arm(true, false))
		select {
		case <-wake:
		case <-time.After(time.Second):
			check("UDP readiness wait", errors.New("one-second deadline"))
		}
		var b [65536]byte
		n, from, err := d.udp.TryReadFrom(b[:])
		check("UDP TryReadFrom after transfer", err)
		if from != d.peer || !bytes.Equal(b[:n], payload) {
			check("UDP original payload/source", fmt.Errorf("n=%d from=%s", n, from))
		}
		n, err = d.udp.TryWriteTo(payload, d.peer, false)
		check("UDP TryWriteTo", err)
		if n != len(payload) {
			check("UDP reverse length", fmt.Errorf("got %d", n))
		}
		check("UDP peer deadline", peerUDP.SetReadDeadline(time.Now().Add(time.Second)))
		n, from, err = peerUDP.ReadFromUDPAddrPort(b[:])
		check("UDP reverse receive", err)
		if from != d.local || !bytes.Equal(b[:n], payload) {
			check("UDP reverse payload/source", fmt.Errorf("n=%d from=%s", n, from))
		}
	}
	if control {
		nativeBefore, err := querySocketTrace(native)
		check("native close control baseline", err)
		if d.tcp != nil {
			check("final TCP Close", d.tcp.Close())
		} else {
			check("final UDP Close", d.udp.Close())
		}
		d.proveClose("exact-native", native, nativeBefore)
		t.Log("SOCKET TRANSFER CONTROL PASS exact original/File/native OS closes; payload/source or payload/FIN verified")
	}
}

func (d *socketEvidence) proveClose(stage string, h windows.Handle, before []socketTraceEntry) {
	d.t.Helper()
	after, err := querySocketTrace(h)
	if err != nil {
		d.t.Fatal(err)
	}
	delta := socketTraceDelta(before, after)
	logSocketTrace(d.t, "close-control/"+stage, delta)
	open := false
	for _, e := range before {
		open = open || e.Handle == h && e.Type == 1 && e.PID == uintptr(os.Getpid()) && e.Stack != [16]uintptr{}
	}
	for _, e := range delta {
		if open && e.Type == 2 && e.Handle == h && e.PID == uintptr(os.Getpid()) && e.Stack != [16]uintptr{} {
			return
		}
	}
	d.failure("OS close control/"+stage, errors.New("missing known OPEN or new CLOSE"))
	d.t.Fatalf("OS close control stage=%s handle=%#x lacked known OPEN/new CLOSE", stage, h)
}

func (d *socketEvidence) goChurn(kind string, family byte) func() {
	d.t.Helper()
	ip := net.IPv4(127, 0, 0, 1)
	if family == '6' {
		ip = net.IPv6loopback
	}
	var h windows.Handle
	var close func() error
	if kind == "GoTCP" {
		listener, err := net.ListenTCP("tcp"+string(family), &net.TCPAddr{IP: ip})
		if err != nil {
			d.t.Fatal(err)
		}
		h, close = diagnosticHandle(d.t, listener), listener.Close
	} else {
		conn, err := net.ListenUDP("udp"+string(family), &net.UDPAddr{IP: ip})
		if err != nil {
			d.t.Fatal(err)
		}
		h, close = diagnosticHandle(d.t, conn), conn.Close
	}
	d.handles = append(d.handles, socketTraceHandle{kind + "-churn-live", h})
	return func() {
		if d.t.Failed() {
			d.failure("before Go churn cleanup", errors.New("see original assertion"))
		}
		if err := close(); err != nil {
			d.t.Errorf("%s churn Close: %v", kind, err)
		}
	}
}
