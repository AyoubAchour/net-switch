//go:build linux

package linux

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"golang.org/x/sys/unix"
)

func TestEpollUDPRepliesAndErrorsKeepOneMapping(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	s := &udpSocket{conn: conn, raw: raw, errors: make(chan platform.DatagramError, 1), done: make(chan struct{})}
	defer s.Close()
	var optionErr error
	if err := raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVERR, 1) }); err != nil || optionErr != nil {
		t.Fatalf("error queue: %v %v", err, optionErr)
	}
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	dst := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	local := s.LocalAddr()
	wakes := make(chan struct{}, 1)
	w, err := s.Watch(func() {
		select {
		case wakes <- struct{}{}:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Detach()
	var data [32]byte
	if _, _, err := s.TryReadFrom(data[:]); !errors.Is(err, platform.ErrWouldBlock) {
		t.Fatalf("idle UDP read blocked or failed: %v", err)
	}
	for _, message := range []string{"first", "second"} {
		if err := w.Arm(true, false); err != nil {
			t.Fatal(err)
		}
		if _, err := peer.WriteToUDPAddrPort([]byte(message), local); err != nil {
			t.Fatal(err)
		}
		select {
		case <-wakes:
		case <-time.After(time.Second):
			t.Fatal("UDP readiness did not wake")
		}
		n, from, err := s.TryReadFrom(data[:])
		if err != nil || string(data[:n]) != message || from != dst || s.LocalAddr() != local {
			t.Fatalf("UDP receive changed data or mapping: %q %v %v", data[:n], from, err)
		}
	}
	reported := make(chan platform.DatagramError, 1)
	s.SetErrorHandler(func(e platform.DatagramError) { reported <- e })
	peer.Close()
	if _, err := s.TryWriteTo([]byte("refused"), dst, false); err != nil {
		t.Fatal(err)
	}
	if err := w.Arm(true, false); err != nil {
		t.Fatal(err)
	}
	select {
	case <-wakes:
	case <-time.After(time.Second):
		t.Fatal("UDP error queue did not wake")
	}
	s.TryReadFrom(data[:])
	select {
	case e := <-reported:
		if e.Destination != dst || !e.Unreachable {
			t.Fatalf("wrong error quotation: %+v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("UDP error queue was not drained")
	}
	if _, _, err := s.TryReadFrom(data[:]); !errors.Is(err, platform.ErrWouldBlock) || s.LocalAddr() != local {
		t.Fatalf("a datagram error destroyed its mapping: %v", err)
	}
	if err := w.Arm(true, false); err != nil {
		t.Fatal(err)
	}
	select {
	case <-wakes:
		t.Fatal("drained UDP error queue kept epoll permanently ready")
	case <-time.After(25 * time.Millisecond):
	}
	if _, err := s.TryWriteTo(nil, netip.MustParseAddrPort("[::1]:53"), false); !errors.Is(err, unix.EAFNOSUPPORT) {
		t.Fatalf("wrong-family UDP did not return an error: %v", err)
	}
}
