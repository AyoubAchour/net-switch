package tcp

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
)

type orderedChannel struct {
	*channel.Endpoint
	after func()
}

func (l *orderedChannel) SetAfterInbound(after func()) { l.after = after }
func (l *orderedChannel) InjectInbound(protocol tcpip.NetworkProtocolNumber, p *gv.PacketBuffer) {
	l.Endpoint.InjectInbound(protocol, p)
	l.after()
}

type channelOut struct{ link *orderedChannel }

func (o channelOut) SetAfterInbound(after func()) { o.link.SetAfterInbound(after) }

func (o channelOut) Send(b []byte) bool {
	p := gv.NewPacketBuffer(gv.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
	defer p.DecRef()
	var list gv.PacketBufferList
	list.PushBack(p)
	n, _ := o.link.WritePackets(list)
	return n == 1
}

func harness(t *testing.T, c flowapi.Controller, d testfake.Dialer) (*Forwarder, func() (*gonet.TCPConn, error)) {
	return harnessPackets(t, c, d, nil)
}

func harnessPackets(t *testing.T, c flowapi.Controller, d testfake.Dialer, observe func(*Forwarder, []byte)) (*Forwarder, func() (*gonet.TCPConn, error)) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	links := [2]*orderedChannel{{Endpoint: channel.New(1024, ns.MTU, "")}, {Endpoint: channel.New(1024, ns.MTU, "")}}
	var stacks [2]*gv.Stack
	for i, l := range links {
		s, err := ns.New(l, ns.DefaultOptions())
		if err != nil {
			t.Fatal(err)
		}
		stacks[i] = s
	}
	appIP := tcpip.AddrFrom4([4]byte{198, 18, 0, 2})
	if err := stacks[0].AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: appIP.WithPrefix()}, gv.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	f := New(ctx, stacks[1], 2, c, &testfake.Owners{}, d, channelOut{links[1]})
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Go(func() {
			for {
				p := links[i].ReadContext(ctx)
				if p == nil {
					return
				}
				v := p.ToView()
				if i == 1 && observe != nil {
					observe(f, v.AsSlice())
				}
				wire := gv.NewPacketBuffer(gv.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), v.AsSlice()...))})
				v.Release()
				p.DecRef()
				links[1-i].InjectInbound(ipv4.ProtocolNumber, wire)
				wire.DecRef()
			}
		})
	}
	t.Cleanup(func() {
		cancel()
		f.Stop()
		for _, s := range stacks {
			s.Close()
		}
		for _, s := range stacks {
			s.Wait()
		}
		f.Wait()
		for _, l := range links {
			l.Close()
		}
		wg.Wait()
	})
	dial := func() (*gonet.TCPConn, error) {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		return gonet.DialTCPWithBind(ctx, stacks[0], tcpip.FullAddress{NIC: 1, Addr: appIP}, tcpip.FullAddress{Addr: tcpip.AddrFrom4([4]byte{203, 0, 113, 7}), Port: 443}, ipv4.ProtocolNumber)
	}
	return f, dial
}

func TestOpenDataHalfClose(t *testing.T) {
	c := &testfake.Controller{Line: "B"}
	remote := make(chan *testfake.Conn, 1)
	d := testfake.Dialer{TCPFunc: func(ctx context.Context, line string, _ netip.AddrPort) (platform.TCPConn, error) {
		if line != "B" {
			t.Error("wrong line")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > DialTimeout {
			t.Error("missing dial deadline")
		}
		a, b := testfake.Pair()
		remote <- b
		return a, nil
	}}
	_, dial := harness(t, c, d)
	app, err := dial()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	r := <-remote
	defer r.Close()
	done := make(chan error, 1)
	go func() {
		b, err := io.ReadAll(r)
		if err == nil && string(b) != "request" {
			err = errors.New("wrong request")
		}
		if err == nil {
			_, err = r.Write([]byte("response after EOF"))
		}
		r.CloseWrite()
		done <- err
	}()
	app.Write([]byte("request"))
	app.CloseWrite()
	b, err := io.ReadAll(app)
	if err != nil || string(b) != "response after EOF" {
		t.Fatalf("half-close lost response: %q %v", b, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if c.Up.Load() != 7 || c.Down.Load() != 18 {
		t.Fatalf("counters %d/%d", c.Up.Load(), c.Down.Load())
	}
}

func TestRejectBeforeDial(t *testing.T) {
	for _, where := range []string{"admission", "policy", "dial"} {
		t.Run(where, func(t *testing.T) {
			c := &testfake.Controller{}
			bad := errors.New("denied")
			if where == "admission" {
				c.Err = bad
			}
			if where == "policy" {
				c.ResolveErr = bad
			}
			d := testfake.Dialer{TCPFunc: func(context.Context, string, netip.AddrPort) (platform.TCPConn, error) {
				if where != "dial" {
					t.Error("dial after rejection")
				}
				return nil, bad
			}}
			_, dial := harness(t, c, d)
			start := time.Now()
			app, err := dial()
			if app != nil {
				app.Close()
			}
			if err == nil || time.Since(start) > time.Second {
				t.Fatalf("reject was not fast: %v", err)
			}
		})
	}
}

func TestDialBeforeHandshake(t *testing.T) {
	c := &testfake.Controller{}
	entered := make(chan struct{})
	release := make(chan struct{})
	d := testfake.Dialer{TCPFunc: func(ctx context.Context, _ string, _ netip.AddrPort) (platform.TCPConn, error) {
		close(entered)
		select {
		case <-release:
			return nil, errors.New("dial failed")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	_, dial := harness(t, c, d)
	done := make(chan error, 1)
	go func() {
		app, err := dial()
		if app != nil {
			app.Close()
		}
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("dial was not reached")
	}
	select {
	case <-done:
		t.Fatal("handshake finished before dial")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("dial failure accepted")
	}
}

func TestTransfer100MB(t *testing.T) {
	if testing.Short() {
		t.Skip("100 MB runs in CI")
	}
	c := &testfake.Controller{}
	remote := make(chan *testfake.Conn, 1)
	d := testfake.Dialer{TCPFunc: func(context.Context, string, netip.AddrPort) (platform.TCPConn, error) {
		a, b := testfake.Pair()
		remote <- b
		return a, nil
	}}
	_, dial := harness(t, c, d)
	app, err := dial()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	r := <-remote
	defer r.Close()
	got := make(chan []byte, 1)
	go func() { h := sha256.New(); io.Copy(h, r); r.CloseWrite(); got <- h.Sum(nil) }()
	want := sha256.New()
	block := make([]byte, 32<<10)
	for i := range block {
		block[i] = byte(i * 31)
	}
	for left := 100_000_000; left > 0; {
		n := min(left, len(block))
		if _, err := app.Write(block[:n]); err != nil {
			t.Fatal(err)
		}
		want.Write(block[:n])
		left -= n
	}
	app.CloseWrite()
	if string(<-got) != string(want.Sum(nil)) {
		t.Fatal("100 MB hash mismatch")
	}
	if c.Up.Load() != 100_000_000 {
		t.Fatal("cumulative count lost")
	}
}

func TestRemoteErrorResetsAppAndReleases(t *testing.T) {
	c := &testfake.Controller{}
	remote := make(chan *testfake.Conn, 1)
	d := testfake.Dialer{TCPFunc: func(context.Context, string, netip.AddrPort) (platform.TCPConn, error) {
		a, b := testfake.Pair()
		remote <- b
		return a, nil
	}}
	_, dial := harness(t, c, d)
	app, err := dial()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	(<-remote).Abort(errors.New("remote reset"))
	app.SetReadDeadline(time.Now().Add(time.Second))
	_, err = app.Read(make([]byte, 1))
	if err == nil || err == io.EOF {
		t.Fatalf("expected RST, got %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for c.Closed.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if c.Closed.Load() != 1 {
		t.Fatal("flow reservation leaked")
	}
}
