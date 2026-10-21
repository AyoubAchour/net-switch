//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"golang.org/x/sys/unix"
)

func TestExpiredNetlinkDeadlineLeavesReadyReplyUnconsumed(t *testing.T) {
	app, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	source := app.LocalAddr().(*net.UDPAddr).AddrPort()
	remote := netip.MustParseAddrPort("192.0.2.1:443")
	socket, err := (*diagPool)(nil).get()
	if err != nil {
		t.Fatal(err)
	}
	defer socket.file.Close()
	// An exact UDP diagnostic request uses the kernel's incoming convention.
	var request [72]byte
	const sequence = 0x51444745
	binary.NativeEndian.PutUint32(request[:], uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:], 20)
	binary.NativeEndian.PutUint16(request[6:], unix.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(request[8:], sequence)
	request[16], request[17] = unix.AF_INET, unix.IPPROTO_UDP
	binary.NativeEndian.PutUint32(request[20:], ^uint32(0))
	binary.BigEndian.PutUint16(request[24:], remote.Port())
	binary.BigEndian.PutUint16(request[26:], source.Port())
	copy(request[28:44], remote.Addr().AsSlice())
	copy(request[44:60], source.Addr().AsSlice())
	for i := 64; i < len(request); i++ {
		request[i] = 255
	}
	if err := unix.Sendto(socket.fd, request[:], 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	poll := []unix.PollFd{{Fd: int32(socket.fd), Events: unix.POLLIN}}
	if n, err := unix.Poll(poll, 1000); err != nil || n != 1 || poll[0].Revents&unix.POLLIN == 0 {
		t.Fatalf("kernel reply was not queued before the expired read: n=%d events=%d err=%v", n, poll[0].Revents, err)
	}
	if err := socket.file.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	var data [4096]byte
	if n, err := readNetlink(socket.file, data[:]); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("RawRead oracle did not reject the ready reply at its expired deadline: n=%d err=%v", n, err)
	}
	for range 2 {
		trace := diagQueryTrace{Sequence: sequence}
		trace.peek(socket.file)
		if !trace.ReplyReady || !trace.ReplyFromKernel || !trace.ReplySequenceMatches || trace.PeekError != "" {
			t.Fatalf("diagnostic peek lost or consumed the queued reply: %+v", trace)
		}
	}
	// Clearing the deadline is an oracle control only, never production.
	if err := socket.file.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := readNetlink(socket.file, data[:])
	if err != nil {
		t.Fatal(err)
	}
	messages, err := syscall.ParseNetlinkMessage(data[:n])
	if err != nil || len(messages) != 1 || messages[0].Header.Seq != sequence || messages[0].Header.Type != 20 {
		t.Fatalf("queued message was not this socket's exact kernel answer: %+v %v", messages, err)
	}
	row, err := parseDiag(messages[0].Data)
	if err != nil || row.local != source || row.cookie == 0 {
		t.Fatalf("queued answer had no independently live socket cookie: %+v %v", row, err)
	}
	t.Logf("expired RawRead hid ready kernel response for %s cookie=%s; repeated diagnostic peeks left it intact", source, row.generation())
}

func TestUDPGenerationFailureHistoryIsBounded(t *testing.T) {
	o := NewOwners()
	defer o.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	for i := range 20 {
		tuple := platform.Tuple{Source: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(10000+i)), Destination: netip.MustParseAddrPort("192.0.2.1:443")}
		o.recordUDPGenerationFailure(ctx, tuple, "exact-query", time.Now(), &diagQueryError{Trace: diagQueryTrace{Stage: "receive", Sequence: uint32(i)}, cause: context.DeadlineExceeded})
	}
	stats := o.Stats().(lookupStats)
	if len(stats.UDPGenerationFailures) != 8 {
		t.Fatalf("retained %d failures, want 8", len(stats.UDPGenerationFailures))
	}
	seen := map[uint16]bool{}
	for _, failure := range stats.UDPGenerationFailures {
		port := failure.Tuple.Source.Port()
		if port < 10012 || port > 10019 || seen[port] || failure.Query == nil || failure.Query.Stage != "receive" || failure.DeadlineNS == 0 {
			t.Fatalf("failure evidence was lost or retained past its bound: %+v", failure)
		}
		seen[port] = true
	}
}
