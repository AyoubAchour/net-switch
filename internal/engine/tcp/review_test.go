package tcp

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func TestAppResetAbortsRemoteInsteadOfFIN(t *testing.T) {
	app, client := testfake.Pair()
	remote, server := testfake.Pair()
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() { done <- Splice(context.Background(), app, remote, func(uint64, uint64) {}, func() {}) }()
	client.Abort(errors.New("app RST"))
	if _, err := server.Read(make([]byte, 1)); err == nil || err == io.EOF {
		t.Fatalf("server saw clean FIN: %v", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("reset not reported")
		}
	case <-time.After(time.Second):
		t.Fatal("splice stuck")
	}
}

func TestIdleRelayReturnsGrowthGrant(t *testing.T) {
	c := flows.New(flows.Defaults(), nil)
	config := policy.Config{Lines: []platform.Line{{ID: "A"}}}
	if _, err := c.Apply(policy.Revision{N: 1, Hash: policy.Hash(config), Config: config}); err != nil {
		t.Fatal(err)
	}
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
	done := make(chan error, 1)
	go func() { _, err := io.CopyN(io.Discard, r, 128<<10); done <- err }()
	if _, err := app.Write(make([]byte, 128<<10)); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for c.Stats().TCPBytes == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if c.Stats().TCPBytes == 0 {
		t.Fatal("busy relay did not grow")
	}
	for c.Stats().TCPBytes != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if g := c.Stats(); g.TCPBytes != 0 || g.Flows != 1 {
		t.Fatal("idle open flow kept its growth grant", g)
	}
}

type heldApplyStore struct{ entered, release chan struct{} }

func (s *heldApplyStore) SaveApplied(a policy.Applied) error {
	if a.N == 2 {
		close(s.entered)
		<-s.release
	}
	return nil
}

func TestSlowPolicyFsyncDoesNotDelayTCPPackets(t *testing.T) {
	store := &heldApplyStore{make(chan struct{}), make(chan struct{})}
	c := flows.New(flows.Defaults(), store)
	config := policy.Config{Lines: []platform.Line{{ID: "A"}}}
	c.Apply(policy.Revision{N: 1, Hash: policy.Hash(config), Config: config})
	remote := make(chan *testfake.Conn, 2)
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
	applied := make(chan error, 1)
	go func() {
		_, err := c.Apply(policy.Revision{N: 2, Hash: policy.Hash(config), Config: config})
		applied <- err
	}()
	<-store.entered
	packets := make(chan error, 1)
	go func() {
		read := make(chan error, 1)
		go func() { _, err := io.ReadFull(r, make([]byte, 4)); read <- err }()
		_, err := app.Write([]byte("data"))
		if err == nil {
			err = <-read
		}
		if err == nil {
			next, e := dial()
			err = e
			if next != nil {
				next.Close()
				(<-remote).Close()
			}
		}
		packets <- err
	}()
	var packetErr error
	select {
	case packetErr = <-packets:
	case <-time.After(100 * time.Millisecond):
		packetErr = errors.New("packets waited for fsync")
	}
	close(store.release)
	if err := <-applied; err != nil {
		t.Fatal(err)
	}
	if packetErr != nil {
		t.Fatal(packetErr)
	}
	t.Log("established payload and a new SYN completed while fsync remained blocked")
}

func TestForwarderSilentDropReleasesAdmission(t *testing.T) {
	l := ns.NewLink()
	s, err := ns.New(l, ns.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	c := &testfake.Controller{}
	f := New(context.Background(), s, 2, c, &testfake.Owners{}, testfake.Dialer{}, l)
	defer func() { f.Stop(); s.Close(); s.Wait(); f.Wait(); l.Close() }()
	// Force upstream's documented true-on-drop path without starting a dial.
	f.forwarder = gtcp.NewForwarder(s, MinimumBuffer, 0, f.open)
	src := tcpip.AddrFrom4([4]byte{198, 18, 0, 2})
	dst := tcpip.AddrFrom4([4]byte{203, 0, 113, 7})
	b := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize+3)
	ip := header.IPv4(b)
	ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(b)), TTL: 64, Protocol: uint8(gtcp.ProtocolNumber), SrcAddr: src, DstAddr: dst})
	ip.SetChecksum(^ip.CalculateChecksum())
	h := header.TCP(b[20:])
	h.Encode(&header.TCPFields{SrcPort: 40000, DstPort: 443, SeqNum: 1000, DataOffset: 20, Flags: header.TCPFlagSyn, WindowSize: 65535})
	copy(h[20:], "SYN")
	h.SetChecksum(^checksum.Checksum(h, header.PseudoHeaderChecksum(gtcp.ProtocolNumber, src, dst, uint16(len(h)))))
	p := gv.NewPacketBuffer(gv.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
	defer p.DecRef()
	p.NetworkHeader().Consume(20)
	p.TransportHeader().Consume(20)
	p.NetworkProtocolNumber = header.IPv4ProtocolNumber
	id := gv.TransportEndpointID{RemoteAddress: src, LocalAddress: dst, RemotePort: 40000, LocalPort: 443}
	if !f.Handle(id, p) || c.Begun.Load() != 1 || c.Closed.Load() != 1 || len(f.pending) != 0 {
		t.Fatal("silent drop leaked admission")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	raw := l.Read(ctx)
	if len(raw) < 40 || header.TCP(raw[20:]).AckNumber() != 1004 {
		t.Fatal("RST did not account for SYN data")
	}
}
