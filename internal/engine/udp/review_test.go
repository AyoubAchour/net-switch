package udp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
)

type costlyOwner struct {
	calls atomic.Uint64
	*liveOwner
}

func (o *costlyOwner) UDP(ctx context.Context, a netip.AddrPort) (platform.Owner, error) {
	o.calls.Add(1)
	select {
	case <-ctx.Done():
		return platform.Owner{}, ctx.Err()
	case <-time.After(5 * time.Millisecond):
	}
	return o.liveOwner.UDP(ctx, a)
}
func TestRejectedUDPCachesCostlyLookupUntilIdentityChanges(t *testing.T) {
	o := &costlyOwner{liveOwner: &liveOwner{value: owner}}
	c := &testfake.Controller{ResolveErr: errors.New("blocked")}
	out := make(chan []byte, 1000)
	n := New(context.Background(), nil, c, o, o, testfake.Dialer{}, testfake.Output{Packets: out}, 9000)
	defer n.Close()
	send(n, dest, []byte("blocked"))
	await(t, out)
	for range 100 {
		send(n, dest, []byte("blocked"))
		await(t, out)
	}
	if o.calls.Load() != 1 {
		t.Fatalf("100 rejected datagrams repeated costly lookup %d times", o.calls.Load())
	}
	next := owner
	next.Generation = "changed"
	o.replace(next)
	n.Reconcile(context.Background())
	send(n, dest, []byte("replacement"))
	await(t, out)
	if o.calls.Load() != 2 {
		t.Fatal("identity change did not invalidate rejection")
	}
	t.Log("101 rejected packets: one 5 ms lookup; identity change triggers exactly one fresh lookup")
}

type errorSocket struct {
	*socket
	errors chan error
}

func (s *errorSocket) WaitReadable(ctx context.Context) error {
	if s.ready != nil {
		return nil
	}
	select {
	case err := <-s.errors:
		return err
	case w := <-s.in:
		s.ready = &w
		return nil
	case <-s.done:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *errorSocket) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	if s.ready != nil {
		return s.socket.ReadFrom(b)
	}
	select {
	case err := <-s.errors:
		return 0, netip.AddrPort{}, err
	case w := <-s.in:
		return copy(b, w.b), w.addr, nil
	case <-s.done:
		return 0, netip.AddrPort{}, net.ErrClosed
	}
}
func TestReadErrorsKeepUDPPublicPort(t *testing.T) {
	c := &testfake.Controller{}
	s := &errorSocket{newSocket(), make(chan error, 2)}
	var opens atomic.Uint64
	d := testfake.Dialer{UDPFunc: func(context.Context, string, bool) (platform.UDPConn, error) { opens.Add(1); return s, nil }}
	out := make(chan []byte, 4)
	n := New(context.Background(), nil, c, &testfake.Owners{Value: owner}, nil, d, testfake.Output{Packets: out}, 9000)
	defer n.Close()
	send(n, dest, []byte("first"))
	await(t, s.out)
	s.errors <- &net.OpError{Op: "read", Net: "udp", Err: syscall.Errno(10040)}
	s.errors <- errors.New("recoverable ICMP receive error")
	deadline := time.Now().Add(time.Second)
	for (n.Oversize.Load() != 1 || n.ReadErrors.Load() != 1) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if n.Oversize.Load() != 1 || n.ReadErrors.Load() != 1 {
		t.Fatal("receive error counters missing")
	}
	s.in <- wire{[]byte("unsolicited after errors"), dest}
	await(t, out)
	send(n, dest, []byte("same public port"))
	await(t, s.out)
	if opens.Load() != 1 || c.Closed.Load() != 0 {
		t.Fatal("receive error replaced mapping")
	}
	s.errors <- net.ErrClosed
	await(t, s.done)
}

type denyNotices struct {
	*testfake.Controller
	notices atomic.Uint64
}

func (c *denyNotices) AllowReject(string) bool { c.notices.Add(1); return false }

type failedSendSocket struct{ *socket }

func (s *failedSendSocket) WriteTo([]byte, netip.AddrPort, bool) (int, error) {
	return 0, &platform.TooBig{MTU: 1280}
}
func TestFailedUDPSendsUseRejectionRateLimit(t *testing.T) {
	c := &denyNotices{Controller: &testfake.Controller{}}
	s := &failedSendSocket{newSocket()}
	d := testfake.Dialer{UDPFunc: func(context.Context, string, bool) (platform.UDPConn, error) { return s, nil }}
	out := make(chan []byte, 64)
	n := New(context.Background(), nil, c, &testfake.Owners{Value: owner}, nil, d, testfake.Output{Packets: out}, 9000)
	defer n.Close()
	for range 50 {
		send(n, dest, []byte("oversized"))
	}
	deadline := time.Now().Add(time.Second)
	for c.notices.Load() != 50 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if c.notices.Load() != 50 {
		t.Fatal("send errors bypassed AllowReject")
	}
	select {
	case <-out:
		t.Fatal("rate-limited ICMP escaped")
	default:
	}
}
