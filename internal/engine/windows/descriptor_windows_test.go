//go:build windows

package winengine

import (
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// This deliberately omits both readiness backends. It distinguishes a socket
// transfer/close problem from IOCP, event selection, and the shared relay.
func TestNativeTransferWithoutReadinessKeepsEndpoint(t *testing.T) {
	hosted(t)
	for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			ip := net.IPv4(127, 0, 0, 1)
			family, kind := windows.AF_INET, windows.SOCK_DGRAM
			if network[len(network)-1] == '6' {
				ip, family = net.IPv6loopback, windows.AF_INET6
			}
			var listener *net.TCPListener
			if network[:3] == "tcp" {
				kind = windows.SOCK_STREAM
				var err error
				listener, err = net.ListenTCP(network, &net.TCPAddr{IP: ip})
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
			}
			// Normal FIN rows remain in TIME_WAIT. Keep this diagnostic small
			// enough for the later, mandatory 2,000-row owner timing fixture.
			for round := range 128 {
				func() {
					var conn interface {
						File() (*os.File, error)
						Close() error
						LocalAddr() net.Addr
					}
					var peer *net.TCPConn
					if listener == nil {
						value, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
						if err != nil {
							t.Fatal(err)
						}
						conn = value
					} else {
						value, err := net.DialTCP(network, nil, listener.Addr().(*net.TCPAddr))
						if err != nil {
							t.Fatal(err)
						}
						conn = value
						peer, err = listener.AcceptTCP()
						if err != nil {
							conn.Close()
							t.Fatal(err)
						}
						defer peer.Close()
					}
					defer conn.Close()
					var wantPort int
					switch addr := conn.LocalAddr().(type) {
					case *net.UDPAddr:
						wantPort = addr.Port
					case *net.TCPAddr:
						wantPort = addr.Port
					}
					file, err := conn.File()
					if err != nil {
						t.Fatal(err)
					}
					defer file.Close()
					source := file.Fd()
					h, err := duplicateForReadiness(file)
					if err != nil {
						t.Fatal(err)
					}
					defer windows.Closesocket(h)
					check := func(stage string) {
						t.Helper()
						gotKind, kindErr := windows.GetsockoptInt(h, windows.SOL_SOCKET, 0x1008)
						addr, addrErr := windows.Getsockname(h)
						var port int
						switch addr := addr.(type) {
						case *windows.SockaddrInet4:
							port = addr.Port
						case *windows.SockaddrInet6:
							port = addr.Port
						}
						if kindErr != nil || gotKind != kind || addrErr != nil || port != wantPort {
							t.Fatalf("round=%d stage=%s source=%d native=%d family=%d type=%d/%d type-error=%v address=%#v want-port=%d address-error=%v",
								round, stage, source, h, family, gotKind, kind, kindErr, addr, wantPort, addrErr)
						}
					}
					check("duplicated")
					if err := conn.Close(); err != nil {
						t.Fatal(err)
					}
					check("Go connection closed")
					if err := file.Close(); err != nil {
						t.Fatal(err)
					}
					check("Go file closed")
					if round%32 == 0 {
						runtime.GC()
						check("GC completed")
					}
					if peer != nil {
						payload := []byte(fmt.Sprintf("native transfer %d", round))
						if n, err := socketIO(h, "send", payload); err != nil || n != len(payload) {
							t.Fatalf("round=%d native send=%d/%d: %v", round, n, len(payload), err)
						}
						check("payload sent")
						if err := windows.Shutdown(h, windows.SHUT_WR); err != nil {
							t.Fatalf("round=%d native half-close without readiness: %v", round, err)
						}
						peer.SetReadDeadline(time.Now().Add(time.Second))
						got, err := io.ReadAll(peer)
						if err != nil || string(got) != string(payload) {
							t.Fatalf("round=%d peer payload/FIN %q: %v", round, got, err)
						}
						check("peer received payload and FIN")
					}
				}()
			}
			t.Log("128 transfers kept type and binding through both source closes; TCP payload and FIN verified")
		})
	}
}

type pausedSocketBorrow struct {
	syscall.RawConn
	entered, resume chan struct{}
}

func (p pausedSocketBorrow) Control(fn func(uintptr)) error {
	return p.RawConn.Control(func(fd uintptr) {
		close(p.entered)
		<-p.resume
		fn(fd)
	})
}

func TestDescriptorTransferHoldsSourceUntilNativeDuplicateExists(t *testing.T) {
	hosted(t)
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	want := conn.LocalAddr().(*net.UDPAddr)
	file, err := conn.File()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	file.Fd()
	raw, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	borrow := pausedSocketBorrow{raw, make(chan struct{}), make(chan struct{})}
	type result struct {
		handle windows.Handle
		err    error
	}
	duplicated := make(chan result, 1)
	go func() {
		handle, err := duplicateBorrowedSocket(borrow)
		duplicated <- result{handle, err}
	}()
	<-borrow.entered
	closed := make(chan error, 1)
	go func() { closed <- file.Close() }()
	deadline := time.Now().Add(time.Second)
	closing := false
	for time.Now().Before(deadline) {
		if raw.Control(func(uintptr) {}) != nil {
			closing = true // Close set the descriptor's closing bit.
			break
		}
		runtime.Gosched()
	}
	if !closing {
		close(borrow.resume)
		t.Fatal("fixture did not begin closing the borrowed descriptor")
	}
	select {
	case err := <-closed:
		close(borrow.resume)
		t.Fatalf("source descriptor closed during native duplication: %v", err)
	default:
	}
	runtime.GC()
	// Attempt to allocate a different socket type while Close is pending.
	// The protected UDP descriptor must not be recycled into this TCP socket.
	other, err := windows.Socket(windows.AF_INET, windows.SOCK_STREAM, windows.IPPROTO_TCP)
	if err != nil {
		close(borrow.resume)
		t.Fatal(err)
	}
	defer windows.Closesocket(other)
	close(borrow.resume)
	copied := <-duplicated
	if copied.err != nil {
		t.Fatal(copied.err)
	}
	defer windows.Closesocket(copied.handle)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	kind, err := windows.GetsockoptInt(copied.handle, windows.SOL_SOCKET, 0x1008) // SO_TYPE.
	if err != nil || kind != windows.SOCK_DGRAM {
		t.Fatalf("native duplicate changed type: %d %v", kind, err)
	}
	address, err := windows.Getsockname(copied.handle)
	bound, ok := address.(*windows.SockaddrInet4)
	if err != nil || !ok || bound.Port != want.Port || bound.Addr != [4]byte{127, 0, 0, 1} {
		t.Fatalf("native duplicate lost source binding: %#v %v", address, err)
	}
	t.Log("native UDP duplicate retained its type and source through concurrent source Close and GC")
}
