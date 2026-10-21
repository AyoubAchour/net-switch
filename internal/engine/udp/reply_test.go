package udp

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
)

type gatedReplySocket struct {
	*socket
	waiting, reading, allowRead chan struct{}
	waitOnce, readOnce          sync.Once
}

func (s *gatedReplySocket) WaitReadable(ctx context.Context) error {
	s.waitOnce.Do(func() { close(s.waiting) })
	return s.socket.WaitReadable(ctx)
}

func (s *gatedReplySocket) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	s.readOnce.Do(func() { close(s.reading) })
	select {
	case <-s.allowRead:
		return s.socket.ReadFrom(b)
	case <-s.done:
		return 0, netip.AddrPort{}, net.ErrClosed
	}
}

func waitReplyState(t *testing.T, condition func() bool) {
	t.Helper()
	until := time.Now().Add(time.Second)
	for !condition() && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if !condition() {
		t.Fatal("reply fixture did not reach the required state")
	}
}

func TestReplyStorageIsBorrowedWhenReadableAndHeldThroughWriterRelease(t *testing.T) {
	c := &testfake.Controller{}
	s := &gatedReplySocket{socket: newSocket(), waiting: make(chan struct{}), reading: make(chan struct{}), allowRead: make(chan struct{})}
	d := testfake.Dialer{UDPFunc: func(context.Context, string, bool) (platform.UDPConn, error) { return s, nil }}
	link := ns.NewLink()
	defer link.Close()
	n := New(context.Background(), nil, c, &testfake.Owners{Value: owner}, nil, d, link, 9000)
	defer n.Close()
	send(n, dest, []byte("open"))
	await(t, s.out)
	await(t, s.waiting)
	waitReplyState(t, func() bool { return c.Pending.Load() == 0 })
	if c.ReadBytes.Load() != 0 {
		t.Fatal("idle session retained a receive buffer")
	}
	payload := make([]byte, 12000)
	s.in <- wire{payload, dest}
	await(t, s.reading)
	if c.ReadBytes.Load() != flowapi.UDPReadBuffer || c.Reply.Load() != flowapi.UDPReadBuffer || c.Pending.Load() != 0 {
		t.Fatal("read buffer was not charged before receiving")
	}
	close(s.allowRead)
	waitReplyState(t, func() bool { return link.Queued() == 2 })
	want := int64(packet.UDPReplySize(dest.Addr(), local.Addr(), len(payload), 9000))
	if c.ReadBytes.Load() != 0 || c.Reply.Load() != want {
		t.Fatalf("queued bytes=%d read bytes=%d, want %d/0", c.Reply.Load(), c.ReadBytes.Load(), want)
	}
	var held [1]ns.OutputPacket
	if link.ReadOwnedBatch(context.Background(), held[:]) != 1 || link.Queued() != 1 {
		t.Fatal("fixture needs queued and writer-owned fragments")
	}
	n.Close()
	if c.Reply.Load() != want || c.Down.Load() != uint64(len(payload)) {
		t.Fatal("session close lost in-flight storage or payload accounting")
	}
	link.Close()
	if c.Reply.Load() != want {
		t.Fatal("link close released storage still held by writer")
	}
	held[0].Release()
	held[0].Release()
	if c.Reply.Load() != 0 || c.ReadBytes.Load() != 0 {
		t.Fatal("final writer release leaked or double-released reply storage")
	}
}

func TestReplyBudgetRefusalKeepsTheMapping(t *testing.T) {
	c := &testfake.Controller{ReplyLimit: flowapi.UDPReadBuffer}
	s := newSocket()
	d := testfake.Dialer{UDPFunc: func(context.Context, string, bool) (platform.UDPConn, error) { return s, nil }}
	link := ns.NewLink()
	defer link.Close()
	n := New(context.Background(), nil, c, &testfake.Owners{Value: owner}, nil, d, link, 9000)
	defer n.Close()
	send(n, dest, []byte("open"))
	await(t, s.out)
	waitReplyState(t, func() bool { return c.Pending.Load() == 0 })
	s.in <- wire{make([]byte, 12000), dest}
	waitReplyState(t, func() bool { return n.Dropped.Load() == 1 })
	if c.Reply.Load() != 0 || c.ReadBytes.Load() != 0 || link.Queued() != 0 || n.Oversize.Load() != 0 {
		t.Fatal("budget refusal allocated output, leaked its read buffer, or misclassified size")
	}
	send(n, dest, []byte("same mapping"))
	await(t, s.out)
	if c.Begun.Load() != 1 || c.Closed.Load() != 0 {
		t.Fatal("reply overload replaced the UDP mapping")
	}
}
