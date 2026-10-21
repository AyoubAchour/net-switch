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

	"github.com/AyoubAchour/net-switch/internal/winhandle"
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
					fileOwner, err := ownGoDescriptor(file, "transfer regression File duplicate")
					if err != nil {
						t.Fatal(err)
					}
					source := fileOwner.Handle("transfer regression source identity")
					h, err := duplicateForReadiness(file, fileOwner)
					if err != nil {
						t.Fatal(err)
					}
					defer h.SocketClose("transfer regression native close")
					check := func(stage string) {
						t.Helper()
						value := h.Handle("transfer regression " + stage)
						gotKind, kindErr := windows.GetsockoptInt(value, windows.SOL_SOCKET, 0x1008)
						addr, addrErr := windows.Getsockname(value)
						var port int
						switch addr := addr.(type) {
						case *windows.SockaddrInet4:
							port = addr.Port
						case *windows.SockaddrInet6:
							port = addr.Port
						}
						if kindErr != nil || gotKind != kind || addrErr != nil || port != wantPort {
							// Diagnostics only: does the source handle still have its
							// state, and does the duplicate still see its peer? This
							// separates a wrong duplicate from a source that already
							// lost its binding. The verdict is unchanged.
							var sourceAddr windows.Sockaddr
							var sourceErr error
							if stage == "duplicated" {
								sourceAddr, sourceErr = windows.Getsockname(source)
							}
							peerAddr, peerErr := windows.Getpeername(value)
							handleFailureEvidence(t, map[string]windows.Handle{"native duplicate": value, "source": source})
							// The close trace (x64 job 119272592603) showed this value
							// was not closed and reused: its newest OS record is its
							// own open. Is it the source's kernel object with stale
							// Winsock state? Read-only comparison, then one refresh of
							// Winsock's connect context. Evidence only.
							sameObject, _, compareErr := windows.NewLazySystemDLL("kernelbase.dll").NewProc("CompareObjectHandles").Call(uintptr(source), uintptr(value))
							t.Logf("SOCKET IDENTITY same-kernel-object=%t compare-error=%v", sameObject != 0, compareErr)
							if kind == windows.SOCK_STREAM {
								refreshErr := windows.Setsockopt(value, windows.SOL_SOCKET, 0x7010 /* SO_UPDATE_CONNECT_CONTEXT */, nil, 0)
								refreshedAddr, refreshedErr := windows.Getsockname(value)
								refreshedPeer, refreshedPeerErr := windows.Getpeername(value)
								t.Logf("SOCKET CONTEXT REFRESH error=%v address=%#v address-error=%v peer=%#v peer-error=%v",
									refreshErr, refreshedAddr, refreshedErr, refreshedPeer, refreshedPeerErr)
							}
							t.Fatalf("round=%d stage=%s source=%d native=%d family=%d type=%d/%d type-error=%v address=%#v want-port=%d address-error=%v source-address=%#v source-error=%v native-peer=%#v native-peer-error=%v",
								round, stage, source, value, family, gotKind, kind, kindErr, addr, wantPort, addrErr, sourceAddr, sourceErr, peerAddr, peerErr)
						}
					}
					check("duplicated")
					if err := conn.Close(); err != nil {
						t.Fatal(err)
					}
					check("Go connection closed")
					if err := fileOwner.CloseGo("transfer regression File close", file.Close); err != nil {
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
						if err := windows.Shutdown(h.Handle("transfer regression shutdown"), windows.SHUT_WR); err != nil {
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
	fileOwner, err := ownGoDescriptor(file, "concurrent-close regression File duplicate")
	if err != nil {
		t.Fatal(err)
	}
	borrow := pausedSocketBorrow{raw, make(chan struct{}), make(chan struct{})}
	type result struct {
		handle winhandle.Owner
		err    error
	}
	duplicated := make(chan result, 1)
	go func() {
		handle, err := duplicateBorrowedSocket(borrow, fileOwner)
		duplicated <- result{handle, err}
	}()
	<-borrow.entered
	closed := make(chan error, 1)
	go func() { closed <- fileOwner.CloseGo("concurrent-close regression source close", file.Close) }()
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
	otherOwner := winhandle.Open(other, "concurrent-close regression TCP socket")
	defer otherOwner.SocketClose("concurrent-close regression TCP close")
	close(borrow.resume)
	copied := <-duplicated
	if copied.err != nil {
		t.Fatal(copied.err)
	}
	defer copied.handle.SocketClose("concurrent-close regression native close")
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	kind, err := windows.GetsockoptInt(copied.handle.Handle("concurrent-close regression socket type"), windows.SOL_SOCKET, 0x1008) // SO_TYPE.
	if err != nil || kind != windows.SOCK_DGRAM {
		t.Fatalf("native duplicate changed type: %d %v", kind, err)
	}
	address, err := windows.Getsockname(copied.handle.Handle("concurrent-close regression address"))
	bound, ok := address.(*windows.SockaddrInet4)
	if err != nil || !ok || bound.Port != want.Port || bound.Addr != [4]byte{127, 0, 0, 1} {
		t.Fatalf("native duplicate lost source binding: %#v %v", address, err)
	}
	t.Log("native UDP duplicate retained its type and source through concurrent source Close and GC")
}
