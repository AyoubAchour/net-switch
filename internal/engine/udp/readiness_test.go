package udp

import (
	"context"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
)

type readyDatagram struct {
	*socket
	mu                sync.Mutex
	wake              func()
	blocked, detached bool
}

type droppedDatagram struct{ *readyDatagram }

func (*droppedDatagram) TryWriteTo([]byte, netip.AddrPort, bool) (int, error) {
	return 0, platform.ErrDatagramDropped
}
func TestLocalUDPSendDropIsCountedWithoutFalseUnreachable(t *testing.T) {
	c := &testfake.Controller{}
	socket := &droppedDatagram{&readyDatagram{socket: newSocket()}}
	out := make(chan []byte, 4)
	n := New(context.Background(), nil, c, &testfake.Owners{Value: owner}, nil, testfake.Dialer{UDPFunc: func(context.Context, string, bool) (platform.UDPConn, error) { return socket, nil }}, testfake.Output{Packets: out}, 9000)
	defer n.Close()
	send(n, dest, []byte("QUIC remains connected"))
	waitReplyState(t, func() bool { return n.Dropped.Load() == 1 && c.Pending.Load() == 0 })
	if len(out) != 0 || c.Up.Load() != 0 {
		t.Fatal("local resource drop fabricated an unreachable or counted sent bytes")
	}
}

func (s *readyDatagram) Watch(wake func()) (platform.Readiness, error) {
	s.mu.Lock()
	s.wake = wake
	s.mu.Unlock()
	return s, nil
}
func (s *readyDatagram) Detach() { s.mu.Lock(); s.detached = true; s.mu.Unlock() }
func (s *readyDatagram) Arm(read, write bool) error {
	s.mu.Lock()
	wake, ready := s.wake, !s.detached && ((read && len(s.in) != 0) || (write && !s.blocked))
	s.mu.Unlock()
	if ready {
		wake()
	}
	return nil
}
func (s *readyDatagram) TryReadFrom(b []byte) (int, netip.AddrPort, error) {
	select {
	case w := <-s.in:
		return copy(b, w.b), w.addr, nil
	default:
		return 0, netip.AddrPort{}, platform.ErrWouldBlock
	}
}
func (s *readyDatagram) TryWriteTo(b []byte, dst netip.AddrPort, df bool) (int, error) {
	s.mu.Lock()
	blocked := s.blocked
	s.mu.Unlock()
	if blocked {
		return 0, platform.ErrWouldBlock
	}
	return s.socket.WriteTo(b, dst, df)
}

func TestReadyUDPSessionsRetainNoIdleGoroutines(t *testing.T) {
	before := runtime.NumGoroutine()
	c := &testfake.Controller{}
	d := testfake.Dialer{UDPFunc: func(context.Context, string, bool) (platform.UDPConn, error) {
		return &readyDatagram{socket: newSocket()}, nil
	}}
	link := ns.NewLink()
	defer link.Close()
	n := New(context.Background(), nil, c, &testfake.Owners{Value: owner}, nil, d, link, 9000)
	defer n.Close()
	const count = 1024
	for i := 0; i < count; i++ {
		source := netip.AddrPortFrom(local.Addr(), uint16(20000+i))
		n.receive(source, dest, 30, func() ([]byte, []byte, bool) {
			return []byte{1}, packet.UDP(source, dest, []byte{1}), false
		})
	}
	deadline := time.Now().Add(5 * time.Second)
	for (c.Up.Load() != count || runtime.NumGoroutine() > before+24) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if c.Up.Load() != count || c.Closed.Load() != 0 || runtime.NumGoroutine() > before+24 {
		t.Fatalf("held UDP sessions: sent=%d closed=%d goroutines=%d baseline=%d", c.Up.Load(), c.Closed.Load(), runtime.NumGoroutine(), before)
	}
	n.Close()
	if c.Closed.Load() != count || c.Pending.Load() != 0 || c.Reply.Load() != 0 {
		t.Fatalf("ready shutdown leaked accounting: %d closed, %d pending, %d reply", c.Closed.Load(), c.Pending.Load(), c.Reply.Load())
	}
}

func TestReadyUDPWriteBackpressureKeepsPacketUntilWritable(t *testing.T) {
	c := &testfake.Controller{}
	socket := &readyDatagram{socket: newSocket(), blocked: true}
	d := testfake.Dialer{UDPFunc: func(context.Context, string, bool) (platform.UDPConn, error) { return socket, nil }}
	link := ns.NewLink()
	defer link.Close()
	n := New(context.Background(), nil, c, &testfake.Owners{Value: owner}, nil, d, link, 9000)
	defer n.Close()
	send(n, dest, []byte("one"))
	send(n, dest, []byte("two"))
	waitReplyState(t, func() bool { socket.mu.Lock(); defer socket.mu.Unlock(); return socket.wake != nil })
	if c.Up.Load() != 0 || c.Pending.Load() != 68 {
		t.Fatalf("blocked datagrams lost their reservation: %d/%d", c.Up.Load(), c.Pending.Load())
	}
	socket.mu.Lock()
	socket.blocked = false
	wake := socket.wake
	socket.mu.Unlock()
	wake()
	for _, want := range []string{"one", "two"} {
		if got := await(t, socket.out); string(got.b) != want {
			t.Fatalf("write order: %q want %q", got.b, want)
		}
	}
	waitReplyState(t, func() bool { return c.Pending.Load() == 0 })
}

func TestPendingFloodCannotConsumeEstablishedReplyBudget(t *testing.T) {
	c := &testfake.Controller{Limit: 32 << 20}
	socket := newSocket()
	d := testfake.Dialer{UDPFunc: func(context.Context, string, bool) (platform.UDPConn, error) { return socket, nil }}
	link := ns.NewLink()
	defer link.Close()
	n := New(context.Background(), nil, c, &testfake.Owners{Value: owner}, nil, d, link, 9000)
	defer n.Close()
	send(n, dest, []byte("established"))
	await(t, socket.out)
	waitReplyState(t, func() bool { return c.Pending.Load() == 0 })
	if !c.ReservePending(32<<20) || c.ReservePending(1) {
		t.Fatal("fixture did not exhaust the first-packet budget")
	}
	defer c.ReleasePending(32 << 20)
	socket.in <- wire{make([]byte, 12000), dest}
	waitReplyState(t, func() bool { return link.Queued() == 2 })
	if c.Pending.Load() != 32<<20 || c.Reply.Load() == 0 || n.Dropped.Load() != 0 {
		t.Fatal("new-session pressure consumed established receive capacity")
	}
}

type installingDatagram struct {
	*readyDatagram
	installing, resume chan struct{}
	closedBeforeDetach atomic.Bool
}

func (s *installingDatagram) Watch(wake func()) (platform.Readiness, error) {
	close(s.installing)
	<-s.resume
	return s.readyDatagram.Watch(wake)
}

func (s *installingDatagram) Close() error {
	s.mu.Lock()
	detached := s.detached
	s.mu.Unlock()
	if !detached {
		s.closedBeforeDetach.Store(true)
	}
	return s.socket.Close()
}

func TestReadyUDPSetupCancellationDetachesBeforeSocketClose(t *testing.T) {
	c := &testfake.Controller{}
	socket := &installingDatagram{readyDatagram: &readyDatagram{socket: newSocket()}, installing: make(chan struct{}), resume: make(chan struct{})}
	d := testfake.Dialer{UDPFunc: func(context.Context, string, bool) (platform.UDPConn, error) { return socket, nil }}
	link := ns.NewLink()
	defer link.Close()
	n := New(context.Background(), nil, c, &testfake.Owners{Value: owner}, nil, d, link, 9000)
	send(n, dest, []byte("cancel during registration"))
	await(t, socket.installing)
	done := make(chan struct{})
	go func() { n.Close(); close(done) }()
	// Establish that cancellation began while Watch was still installing.
	await(t, n.ctx.Done())
	close(socket.resume)
	await(t, done)
	if socket.closedBeforeDetach.Load() || c.Closed.Load() != 1 || c.Pending.Load() != 0 {
		t.Fatalf("setup cancellation violated ownership: early close=%t tickets=%d pending=%d", socket.closedBeforeDetach.Load(), c.Closed.Load(), c.Pending.Load())
	}
}
