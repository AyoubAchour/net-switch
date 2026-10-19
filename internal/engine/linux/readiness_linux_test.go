//go:build linux

package linux

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"golang.zx2c4.com/wireguard/tun"
)

type errorBatchTun struct {
	tun.Device
	reads int
}

func (d *errorBatchTun) Read(b [][]byte, sizes []int, _ int) (int, error) {
	d.reads++
	switch d.reads {
	case 1:
		for i := range 2 {
			sizes[i] = copy(b[i], []byte{byte(i + 1)})
		}
		return 2, tun.ErrTooManySegments
	case 2:
		return 0, errors.New("bad virtio header")
	case 3:
		sizes[0] = copy(b[0], []byte{3})
		return 1, nil
	default:
		return 0, os.ErrClosed
	}
}

func TestTunReadDropsKeepReturnedSegmentsAndContinue(t *testing.T) {
	d := &errorBatchTun{}
	tun := &Tun{device: d, sizes: make([]int, 2), bufs: [][]byte{make([]byte, 16), make([]byte, 16)}}
	var data [16]byte
	for _, want := range []byte{1, 2, 0, 3} {
		n, err := tun.ReadPacket(context.Background(), data[:])
		if err != nil || (want == 0 && n != 0) || (want != 0 && (n != 1 || data[0] != want)) {
			t.Fatalf("want segment %d, got %x, %v", want, data[:n], err)
		}
	}
	if _, err := tun.ReadPacket(context.Background(), data[:]); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closure: %v", err)
	}
	if tun.readErrors.Load() != 2 {
		t.Fatalf("read drops: %d", tun.readErrors.Load())
	}
}

func TestEpollReadinessPartialDataEOFAndDetach(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	peer, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	raw, err := client.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	socket := &tcpSocket{TCPConn: client, raw: raw}
	wakes := make(chan struct{}, 1)
	w, err := socket.Watch(func() {
		select {
		case wakes <- struct{}{}:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Detach()
	var data [8]byte
	if _, err := socket.TryRead(data[:]); !errors.Is(err, platform.ErrWouldBlock) {
		t.Fatalf("idle read: %v", err)
	}
	for _, part := range []string{"first", "second"} {
		if err := w.Arm(true, false); err != nil {
			t.Fatal(err)
		}
		if _, err := peer.Write([]byte(part)); err != nil {
			t.Fatal(err)
		}
		select {
		case <-wakes:
		case <-time.After(time.Second):
			t.Fatal("lost read wake")
		}
		n, err := socket.TryRead(data[:])
		if err != nil || string(data[:n]) != part {
			t.Fatalf("read: %q, %v", data[:n], err)
		}
	}
	if err := w.Arm(true, false); err != nil {
		t.Fatal(err)
	}
	peer.CloseWrite()
	select {
	case <-wakes:
	case <-time.After(time.Second):
		t.Fatal("lost EOF wake")
	}
	if _, err := socket.TryRead(data[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("EOF: %v", err)
	}
	if _, err := socket.TryWrite([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(peer, data[:5]); err != nil || string(data[:5]) != "reply" {
		t.Fatalf("half close lost reply: %v", err)
	}
	w.Detach()
	client.Close()
	if err := w.Arm(true, true); err != nil {
		t.Fatalf("detached registration rearmed: %v", err)
	}
}
