//go:build windows

package winengine

import (
	"net"
	"runtime"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

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
