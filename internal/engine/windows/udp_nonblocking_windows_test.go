//go:build windows

package winengine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/winclock"
	"golang.org/x/sys/windows"
)

func udpReceiveDiagnostic(t *testing.T, s *udpSocket) {
	t.Helper()
	local, localErr := windows.Getsockname(s.handle)
	kind, kindErr := windows.GetsockoptInt(s.handle, windows.SOL_SOCKET, 0x1008) // SO_TYPE.
	// Diagnostic only: the original test still fails. This independent
	// documented nonblocking API distinguishes socket state from WSARecvFrom
	// argument handling; it is never a production retry.
	b := make([]byte, 65536)
	n, peer, err := windows.Recvfrom(s.handle, b, 0)
	var digest [32]byte
	if n >= 0 && n <= len(b) {
		digest = sha256.Sum256(b[:n])
	}
	t.Logf("UDP receive failure diagnostic: handle=%d cached=%s native=%#v native-error=%v type=%d type-error=%v recvfrom-n=%d peer=%#v hash=%x error=%v",
		s.handle, s.local, local, localErr, kind, kindErr, n, peer, digest, err)
}

func nativeUDPPair(t *testing.T, network string) (*udpSocket, *net.UDPConn) {
	t.Helper()
	hosted(t)
	pool, err := newUDPReadiness(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pool.close(); err != nil {
			t.Error(err)
		}
	})
	address := net.IPv4(127, 0, 0, 2)
	peerAddress := net.IPv4(127, 0, 0, 1)
	if network == "udp6" {
		address, peerAddress = net.IPv6loopback, net.IPv6loopback
	}
	conn, err := net.ListenUDP(network, &net.UDPAddr{IP: address})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	s := &udpSocket{conn: conn, raw: raw, pool: pool, local: conn.LocalAddr().(*net.UDPAddr).AddrPort(), v6: network == "udp6", mtu: 65535}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	peer, err := net.ListenUDP(network, &net.UDPAddr{IP: peerAddress})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	return s, peer
}

func udpWake(t *testing.T, wakes <-chan struct{}) {
	t.Helper()
	select {
	case <-wakes:
	case <-time.After(time.Second):
		t.Fatal("UDP readiness stalled")
	}
}

func noUDPWake(t *testing.T, wakes <-chan struct{}) {
	t.Helper()
	winclock.System.Wait(context.Background(), 10*time.Millisecond)
	select {
	case <-wakes:
		t.Fatal("empty/disarmed socket produced readiness")
	default:
	}
}

func TestReadyUDPDoesNotConsumeDatagrams(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		maximum := 65507
		if network == "udp6" {
			maximum = 65527
		}
		for _, size := range []int{0, 1, 12000, 65000, maximum} {
			for _, immediate := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s/%d/immediate=%t", network, size, immediate), func(t *testing.T) {
					s, peer := nativeUDPPair(t, network)
					payload := make([]byte, size)
					for i := range payload {
						payload[i] = byte(i*37 + 11)
					}
					send := func() {
						t.Helper()
						if n, err := peer.WriteToUDPAddrPort(payload, s.LocalAddr()); err != nil || n != len(payload) {
							t.Fatalf("native send precondition: %d %v", n, err)
						}
					}
					if immediate {
						send() // Queued before descriptor transfer and event installation.
					}
					wakes := make(chan struct{}, 1)
					watch, err := s.Watch(func() {
						select {
						case wakes <- struct{}{}:
						default:
						}
					})
					if err != nil {
						t.Fatal(err)
					}
					b := make([]byte, 65536)
					if !immediate {
						if n, source, err := s.TryReadFrom(b); n != 0 || source.IsValid() || !errors.Is(err, platform.ErrWouldBlock) {
							udpReceiveDiagnostic(t, s)
							t.Fatalf("empty queue: n=%d source=%s err=%v", n, source, err)
						}
					}
					if err := watch.Arm(true, false); err != nil {
						t.Fatal(err)
					}
					if !immediate {
						noUDPWake(t, wakes)
						send()
					}
					udpWake(t, wakes)
					// Rearm without consuming: the same datagram must stay readable.
					if err := watch.Arm(true, false); err != nil {
						t.Fatal(err)
					}
					udpWake(t, wakes)
					n, source, err := s.TryReadFrom(b)
					wantSource := peer.LocalAddr().(*net.UDPAddr).AddrPort()
					if err != nil || source != wantSource || !bytes.Equal(b[:n], payload) {
						udpReceiveDiagnostic(t, s)
						t.Fatalf("changed datagram: n=%d source=%s/%s err=%v", n, source, wantSource, err)
					}
					if n, source, err := s.TryReadFrom(b); n != 0 || source.IsValid() || !errors.Is(err, platform.ErrWouldBlock) {
						udpReceiveDiagnostic(t, s)
						t.Fatalf("datagram was duplicated: n=%d source=%s err=%v", n, source, err)
					}
					// Cancellation is a one-shot interest replacement, with no
					// receive operation whose cleanup could discard the datagram.
					if err := watch.Arm(true, false); err != nil {
						t.Fatal(err)
					}
					if err := watch.Arm(false, false); err != nil {
						t.Fatal(err)
					}
					send()
					noUDPWake(t, wakes)
					if err := watch.Arm(true, false); err != nil {
						t.Fatal(err)
					}
					udpWake(t, wakes)
					n, source, err = s.TryReadFrom(b)
					if err != nil || source != wantSource || !bytes.Equal(b[:n], payload) {
						udpReceiveDiagnostic(t, s)
						t.Fatalf("cancel/rearm changed payload or source: %d %s %v", n, source, err)
					}
					if network == "udp4" || size <= 65000 {
						if err := watch.Arm(false, true); err != nil {
							t.Fatal(err)
						}
						udpWake(t, wakes)
						if n, err := s.TryWriteTo(payload, wantSource, false); err != nil || n != len(payload) {
							t.Fatalf("nonblocking send: %d %v", n, err)
						}
						peer.SetReadDeadline(time.Now().Add(time.Second))
						n, source, err := peer.ReadFromUDPAddrPort(b)
						if err != nil || source != s.LocalAddr() || !bytes.Equal(b[:n], payload) {
							t.Fatalf("reply changed payload/source: %d %s %v", n, source, err)
						}
					}
					if err := watch.Arm(true, false); err != nil {
						t.Fatal(err)
					}
					watch.Detach()
					if err := s.Close(); err != nil {
						t.Fatal(err)
					}
					if err := watch.Arm(true, true); !errors.Is(err, net.ErrClosed) {
						t.Fatalf("detached watch rearmed: %v", err)
					}
					if _, _, err := s.TryReadFrom(b); !errors.Is(err, net.ErrClosed) {
						t.Fatalf("closed socket read: %v", err)
					}
					t.Logf("documented event/poll readiness preserved %s %d bytes sha256=%x source=%s across rearm and cancellation; closed cleanly",
						network, size, sha256.Sum256(payload), wantSource)
				})
			}
		}
	}
}

// One shared event must not lose another socket's notification when a watch is
// rearmed or detached. Idle watches must not each retain a waiter goroutine.
func TestReadyUDPSharedEventAndIdleCost(t *testing.T) {
	hosted(t)
	before := runtime.NumGoroutine()
	pool, err := newUDPReadiness(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pool.close(); err != nil {
			t.Error(err)
		}
	})
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	const count = 256
	sockets := make([]*udpSocket, count)
	watches := make([]platform.Readiness, count)
	wakes := make(chan int, count*2)
	for i := range sockets {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := conn.SyscallConn()
		if err != nil {
			conn.Close()
			t.Fatal(err)
		}
		s := &udpSocket{conn: conn, raw: raw, pool: pool, local: conn.LocalAddr().(*net.UDPAddr).AddrPort(), mtu: 65535}
		t.Cleanup(func() {
			if err := s.Close(); err != nil {
				t.Error(err)
			}
		})
		watch, err := s.Watch(func() { wakes <- i })
		if err != nil {
			t.Fatal(err)
		}
		sockets[i], watches[i] = s, watch
		if err := watch.Arm(true, false); err != nil {
			t.Fatal(err)
		}
	}
	idle := runtime.NumGoroutine()
	if growth := idle - before; growth > 8 {
		t.Fatalf("idle native UDP watches retained goroutines: before=%d after=%d growth=%d", before, idle, growth)
	}
	wantSource := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	for round := range 4 {
		for i, s := range sockets {
			if s == nil {
				continue
			}
			payload := []byte{byte(i), byte(round), 0xa7}
			if _, err := peer.WriteToUDPAddrPort(payload, s.LocalAddr()); err != nil {
				t.Fatal(err)
			}
		}
		want := count
		if round > 0 {
			want = count / 2
		}
		seen := make(map[int]bool, want)
		for range want {
			var i int
			select {
			case i = <-wakes:
			case <-time.After(2 * time.Second):
				t.Fatalf("shared event lost a wake: round=%d got=%d want=%d", round, len(seen), want)
			}
			if seen[i] || sockets[i] == nil {
				t.Fatalf("duplicate or detached readiness: round=%d socket=%d", round, i)
			}
			seen[i] = true
			var b [16]byte
			n, source, err := sockets[i].TryReadFrom(b[:])
			if err != nil || source != wantSource || !bytes.Equal(b[:n], []byte{byte(i), byte(round), 0xa7}) {
				udpReceiveDiagnostic(t, sockets[i])
				t.Fatalf("shared event changed datagram: round=%d socket=%d n=%d source=%s err=%v", round, i, n, source, err)
			}
			if round == 0 && i%2 == 0 {
				watches[i].Detach()
				if err := sockets[i].Close(); err != nil {
					t.Fatal(err)
				}
				sockets[i] = nil
			} else if err := watches[i].Arm(true, false); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Logf("256 idle native watches: goroutines=%d -> %d; four exact-payload rounds survived interleaved detach/rearm", before, idle)
}
