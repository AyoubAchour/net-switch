package udp

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
)

var local = netip.MustParseAddrPort("198.18.0.2:40000")
var dest = netip.MustParseAddrPort("203.0.113.7:3478")
var owner = platform.Owner{PID: 10, StartTime: 20, AppID: "first", Generation: "socket1"}

type wire struct {
	b    []byte
	addr netip.AddrPort
}
type socket struct {
	out, in chan wire
	done    chan struct{}
	once    sync.Once
	ready   *wire
}

func newSocket() *socket {
	return &socket{out: make(chan wire, 256), in: make(chan wire, 256), done: make(chan struct{})}
}
func (s *socket) WaitReadable(ctx context.Context) error {
	if s.ready != nil {
		return nil
	}
	select {
	case w := <-s.in:
		s.ready = &w
		return nil
	case <-s.done:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *socket) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	if s.ready != nil {
		w := *s.ready
		s.ready = nil
		return copy(b, w.b), w.addr, nil
	}
	select {
	case w := <-s.in:
		return copy(b, w.b), w.addr, nil
	case <-s.done:
		return 0, netip.AddrPort{}, net.ErrClosed
	}
}
func (s *socket) WriteTo(b []byte, a netip.AddrPort, _ bool) (int, error) {
	select {
	case s.out <- wire{append([]byte(nil), b...), a}:
		return len(b), nil
	case <-s.done:
		return 0, io.ErrClosedPipe
	}
}
func (s *socket) Close() error            { s.once.Do(func() { close(s.done) }); return nil }
func (*socket) LocalAddr() netip.AddrPort { return netip.MustParseAddrPort("192.0.2.1:45000") }

type identity struct {
	mu    sync.Mutex
	value platform.Owner
	err   error
	keys  []netip.AddrPort
}

func (i *identity) Snapshot(_ context.Context, keys []netip.AddrPort) (map[netip.AddrPort]platform.Owner, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.keys = append([]netip.AddrPort(nil), keys...)
	return map[netip.AddrPort]platform.Owner{local: i.value}, i.err
}
func (i *identity) set(o platform.Owner) { i.mu.Lock(); i.value = o; i.mu.Unlock() }
func send(n *NAT, a netip.AddrPort, b []byte) {
	n.receive(local, a, len(b), func() ([]byte, []byte, bool) { return append([]byte(nil), b...), packet.UDP(local, a, b), false })
}
func await[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}
	var v T
	return v
}

func setup(t *testing.T, owners *testfake.Owners) (*NAT, *testfake.Controller, chan *socket, chan []byte, *identity, *atomic.Uint64) {
	t.Helper()
	c := &testfake.Controller{Line: "A"}
	sockets := make(chan *socket, 10)
	out := make(chan []byte, 10000)
	ids := &identity{value: owner}
	calls := &atomic.Uint64{}
	d := testfake.Dialer{UDPFunc: func(context.Context, string, bool) (platform.UDPConn, error) {
		calls.Add(1)
		s := newSocket()
		sockets <- s
		return s, nil
	}}
	n := New(context.Background(), nil, c, owners, ids, d, testfake.Output{Packets: out}, 9000)
	t.Cleanup(n.Close)
	return n, c, sockets, out, ids, calls
}

func TestOneMappingAcross50DestinationsAndUnsolicitedReply(t *testing.T) {
	gate := make(chan struct{})
	n, c, sockets, out, _, calls := setup(t, &testfake.Owners{Value: owner, Gate: gate})
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() { send(n, netip.AddrPortFrom(dest.Addr(), uint16(3000+i)), []byte{byte(i)}) })
	}
	wg.Wait()
	close(gate)
	s := await(t, sockets)
	seen := map[uint16]bool{}
	for range 50 {
		w := await(t, s.out)
		seen[w.addr.Port()] = true
	}
	if len(seen) != 50 || calls.Load() != 1 || c.Resolved.Load() != 1 {
		t.Fatal("first packets did not share one mapping and decision")
	}
	third := netip.MustParseAddrPort("203.0.113.99:9999")
	s.in <- wire{[]byte("unsolicited"), third}
	raw := await(t, out)
	src, dst, proto, off, total, ok := packet.IPHeader(raw, false)
	if !ok || src != third.Addr() || dst != local.Addr() || proto != 17 || string(raw[off+8:total]) != "unsolicited" || packet.Sum(raw[off:total], packet.Pseudo(src, dst, 17, total-off)) != 65535 {
		t.Fatal("bad unsolicited reply")
	}
	n.Close()
	if c.Pending.Load() != 0 || c.Begun.Load() != c.Closed.Load() {
		t.Fatal("reservation leaked")
	}
}

func TestPendingSessionRetainsItsIdentityCacheReference(t *testing.T) {
	gate := make(chan struct{})
	n, c, sockets, _, ids, _ := setup(t, &testfake.Owners{Value: owner, Gate: gate})
	send(n, dest, []byte("pending"))
	if c.Pending.Load() == 0 {
		t.Fatal("pending packet wasn't present before reconciliation")
	}
	ids.set(platform.Owner{})
	n.Reconcile(context.Background())
	ids.mu.Lock()
	keys := append([]netip.AddrPort(nil), ids.keys...)
	ids.mu.Unlock()
	if len(keys) != 1 || keys[0] != local {
		t.Fatalf("pending cache reference omitted: %v", keys)
	}
	ids.set(owner)
	close(gate)
	s := await(t, sockets)
	if sent := await(t, s.out); string(sent.b) != "pending" {
		t.Fatalf("pending mapping didn't survive reconciliation: %+v", sent)
	}
}

func TestPendingQueueAndBytes(t *testing.T) {
	for _, large := range []bool{false, true} {
		t.Run(map[bool]string{false: "packets", true: "bytes"}[large], func(t *testing.T) {
			gate := make(chan struct{})
			n, c, _, _, _, _ := setup(t, &testfake.Owners{Value: owner, Gate: gate})
			b := []byte{1}
			if large {
				b = make([]byte, 5000)
			}
			for range 100 {
				send(n, dest, b)
			}
			if n.Dropped.Load() == 0 || c.Pending.Load() > PendingBytes {
				t.Fatal("pending limit not enforced")
			}
			n.Close()
			close(gate)
			if c.Pending.Load() != 0 {
				t.Fatal("pending bytes leaked")
			}
		})
	}
}

func TestReuseAndLateDestroy(t *testing.T) {
	o := &testfake.Owners{Value: owner}
	n, c, sockets, _, ids, _ := setup(t, o)
	send(n, dest, []byte("first"))
	s := await(t, sockets)
	await(t, s.out)
	replacement := owner
	replacement.AppID = "opposite pin"
	replacement.Generation = "socket2"
	ids.set(replacement)
	n.Reconcile(context.Background())
	select {
	case <-s.done:
	default:
		t.Fatal("changed identity survived")
	}
	o.Value = replacement // No lookup is running: the old session has been invalidated.
	send(n, dest, []byte("second"))
	s2 := await(t, sockets)
	await(t, s2.out)
	n.Destroy(local, "socket1")
	select {
	case <-s2.done:
		t.Fatal("late destroy closed replacement")
	default:
	}
	if c.Resolved.Load() != 2 {
		t.Fatal("port reuse kept old decision")
	}
}

func TestStaleIdentityStopsBothDirections(t *testing.T) {
	n, _, sockets, out, ids, _ := setup(t, &testfake.Owners{Value: owner})
	send(n, dest, []byte("first"))
	s := await(t, sockets)
	await(t, s.out)
	b := n.bucket(local)
	b.Lock()
	ss := b.m[local]
	b.Unlock()
	ss.mu.Lock()
	ss.validated = time.Now().Add(-IdentityMaxAge)
	ss.mu.Unlock()
	ids.mu.Lock()
	ids.err = errors.New("stalled dump")
	ids.mu.Unlock()
	send(n, dest, []byte("stale"))
	s.in <- wire{[]byte("stale"), dest}
	deadline := time.Now().Add(time.Second)
	for n.Dropped.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if n.Dropped.Load() != 2 {
		t.Fatal("stale identity still forwarding")
	}
	select {
	case <-s.out:
		t.Fatal("stale send")
	case <-out:
		t.Fatal("stale reply")
	default:
	}
}

func TestBlockedContinuousUDPRejectedFast(t *testing.T) {
	n, c, _, out, _, calls := setup(t, &testfake.Owners{Value: owner})
	c.ResolveErr = errors.New("blocked")
	start := time.Now()
	for range 100 {
		send(n, dest, []byte("blocked"))
		await(t, out)
	}
	if calls.Load() != 0 || time.Since(start) > time.Second {
		t.Fatal("blocked UDP did not fail fast")
	}
}

func TestIdleAndAppICMP(t *testing.T) {
	n, _, sockets, _, _, _ := setup(t, &testfake.Owners{Value: owner})
	send(n, dest, []byte("first"))
	s := await(t, sockets)
	await(t, s.out)
	reply := packet.UDP(dest, local, []byte("reply"))
	icmp := packet.Unreachable(reply, 0)
	if !n.ObserveICMP(icmp) {
		t.Fatal("valid app port-unreachable ignored")
	}
	select {
	case <-s.done:
	default:
		t.Fatal("ICMP did not close session")
	}
	send(n, dest, []byte("next"))
	s2 := await(t, sockets)
	await(t, s2.out)
	b := n.bucket(local)
	b.Lock()
	ss := b.m[local]
	b.Unlock()
	ss.mu.Lock()
	ss.last = time.Now().Add(-IdleTimeout)
	ss.mu.Unlock()
	n.Reconcile(context.Background())
	select {
	case <-s2.done:
	default:
		t.Fatal("idle session survived")
	}
}
