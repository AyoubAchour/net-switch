package stack_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func TestCloseRetainedHalfCloseRead(t *testing.T) {
	clock := faketime.NewManualClock()
	o := ns.DefaultOptions()
	o.Clock = clock
	limits := flows.Defaults()
	limits.Flows, limits.PerApp, limits.TimeWait = 1, 1, 1
	p := newPeerOptions(t, false, limits, o)
	p.open(1000)
	p.upload([]byte("fill retained cap"))
	p.prepareFinalACK(false)
	if g := p.table.Stats(); g.TimeWait != 1 || g.Flows != 0 {
		t.Fatal("retained cap not full", g)
	}
	p.port++

	// A real second TCP stack receives and ACKs the reply before the app reads
	// any bytes. No OS sockets, devices, routes, or synthetic receive buffers.
	appLink := ns.NewLink()
	appStack, err := ns.New(appLink, o)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	ackGate, gotFIN := make(chan struct{}), make(chan struct{})
	releaseACK := sync.OnceFunc(func() { close(ackGate) })
	var finalACK atomic.Uint32
	var wg sync.WaitGroup
	t.Cleanup(func() {
		releaseACK()
		cancel()
		wg.Wait()
		appStack.Close()
		appStack.Wait()
		appLink.Close()
	})
	pump := func(from, to *ns.Link, toApp bool) {
		defer wg.Done()
		for {
			raw := from.Read(ctx)
			if raw == nil {
				return
			}
			ip := header.IPv4(raw)
			h := header.TCP(raw[ip.HeaderLength():])
			fin := toApp && h.Flags().Contains(header.TCPFlagFin)
			if fin {
				finalACK.Store(h.SequenceNumber() + uint32(len(h)-int(h.DataOffset())) + 1)
			}
			if !toApp && finalACK.Load() != 0 && h.AckNumber() == finalACK.Load() {
				select {
				case <-ackGate:
				case <-ctx.Done():
					return
				}
			}
			pkt := gv.NewPacketBuffer(gv.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
			to.InjectInbound(header.IPv4ProtocolNumber, pkt)
			pkt.DecRef()
			if fin {
				close(gotFIN) // Manual clock: no retransmissions before read.
			}
		}
	}
	wg.Add(2)
	go pump(p.link, appLink, true)
	go pump(appLink, p.link, false)
	app, err := gonet.DialTCPWithBind(ctx, appStack,
		tcpip.FullAddress{NIC: ns.NIC, Addr: appAddr, Port: p.port},
		tcpip.FullAddress{NIC: ns.NIC, Addr: remoteAddr, Port: 443}, header.IPv4ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	app.SetReadDeadline(time.Now().Add(5 * time.Second))
	p.current = <-p.accepted
	defer p.current.conn.Close()
	// Wait for normal endpoint setup through a real request, then half-close.
	request := []byte("reply after EOF")
	if _, err := app.Write(request); err != nil {
		t.Fatal(err)
	}
	gotRequest := make([]byte, len(request))
	if _, err := io.ReadFull(p.current.conn, gotRequest); err != nil || !bytes.Equal(gotRequest, request) {
		t.Fatal("request did not reach the server", err)
	}
	if err := app.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	p.receiveEOF()
	ep := p.endpoint()
	payload := bytes.Repeat([]byte("unread reply tail."), 1024)
	if _, err := p.current.conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	// All reply bytes have reached the app TCP receive queue and been ACKed,
	// but the app has not called Read. The regression resets exactly here.
	appEP := appStack.FindTransportEndpoint(header.IPv4ProtocolNumber, tcp.ProtocolNumber,
		gv.TransportEndpointID{LocalAddress: appAddr, LocalPort: p.port, RemoteAddress: remoteAddr, RemotePort: 443}, ns.NIC).(*tcp.Endpoint)
	for {
		n, err := appEP.GetSockOptInt(tcpip.ReceiveQueueSizeOption)
		if err != nil || ctx.Err() != nil {
			t.Fatal("app receive queue did not fill", n, err, ctx.Err())
		}
		if n == len(payload) {
			break
		}
		runtime.Gosched()
	}
	awaitSendBuffer(t, ep, 0)
	if err := p.current.conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	closeSignal(t, p.current.sentEOF, "reply FIN after acknowledged payload")
	closeSignal(t, gotFIN, "app received FIN")
	if g := p.table.Stats(); g.Flows != 0 || g.TimeWait != 1 || g.ClosingOverflow != 1 || p.stack.Stats().TCP.ResetsSent.Value() != 0 {
		t.Fatal("overflow reset would discard the app's unread reply", p.diagnostics())
	}
	reply, err := io.ReadAll(app)
	if err != nil || len(reply) != len(payload) || sha256.Sum256(reply) != sha256.Sum256(payload) {
		t.Fatalf("half-close read: %d/%d bytes, err=%v", len(reply), len(payload), err)
	}
	releaseACK()
	// The ingress fence handles the final ACK; observe its completion via a
	// condition, without advancing time or giving the timeout credit.
	deadline := time.Now().Add(time.Second)
	for !closedEndpoint(ep) && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if !closedEndpoint(ep) || p.table.Stats().ClosingOverflow != 0 || p.stack.Stats().TCP.ResetsSent.Value() != 0 {
		t.Fatal("final ACK did not close cleanly", p.diagnostics())
	}
	t.Logf("app half-closed, left %d reply bytes unread through FIN at full cap, then read every byte with matching SHA-256; RST=0", len(reply))
}

func closedEndpoint(ep *tcp.Endpoint) bool {
	return tcp.EndpointState(ep.State()) == tcp.StateClose
}

func TestCloseRetainedOverflowBound(t *testing.T) {
	closeRetainedOverflowBound(t, 1, 4)
}

func TestCloseRetainedOverflowLoad(t *testing.T) {
	if os.Getenv("NETSWITCH_TIMEWAIT_GATE") != "1" {
		t.Skip("default-cap overflow load runs in CI")
	}
	closeRetainedOverflowBound(t, flows.DefaultTimeWait, 200)
}

func closeRetainedOverflowBound(t *testing.T, retainedCap, burst int) {
	t.Helper()
	clock := faketime.NewManualClock()
	o := ns.DefaultOptions()
	o.Clock = clock
	limits := flows.Defaults()
	limits.Flows, limits.PerApp, limits.TimeWait = 1, 1, retainedCap
	p := newPeerOptions(t, false, limits, o)
	for range retainedCap {
		p.port++
		p.open(1000)
		p.upload([]byte("retain"))
		p.closeActive()
	}
	if g := p.table.Stats(); g.TimeWait != retainedCap || g.Flows != 0 {
		t.Fatal("retained cap not full before overflow load", g)
	}
	// Offer five bursts per second, never ACK their FINs. Close just after a
	// sweep so the test also covers its 250 ms quantization, not only exact
	// deadline alignment. A burst of four means at most seven bursts fit in
	// the 1.25 s retention window, independent of the run length.
	const rounds = 15
	bound := 7 * burst
	clock.Advance(time.Millisecond)
	peak := 0
	for i := range rounds {
		for j := range burst {
			p.port++
			p.open(uint32(2000 + i*burst + j))
			p.upload([]byte("bounded"))
			p.prepareFinalACK(false)
			p.current.conn.Close()
		}
		g := p.table.Stats()
		peak = max(peak, g.ClosingOverflow)
		if g.Flows != 0 || g.TimeWait != retainedCap || g.ClosingOverflow > bound || g.Rejected != 0 {
			t.Fatal("overflow exceeded its close-rate bound", g)
		}
		if n := len(p.stack.RegisteredEndpoints()); n != retainedCap+g.ClosingOverflow {
			t.Fatal("overflow gauge missed retained endpoints", n, g)
		}
		clock.Advance(200 * time.Millisecond)
		// Expired endpoints send resets to older ports. Read those separately
		// so the next handshake cannot accidentally consume a stale reset.
		drainClosePackets(p)
	}
	if peak < 5*burst || p.table.Stats().ClosingOverflowPeak != peak {
		t.Fatal("load did not exercise a full second of overflow", peak, p.table.Stats())
	}
	clock.Advance(1250 * time.Millisecond)
	if g := p.table.Stats(); g.ClosingOverflow != 0 || g.TimeWait != retainedCap || g.Rejected != 0 || p.stack.Stats().TCP.ResetsSent.Value() != uint64(burst*rounds) {
		t.Fatal("expired overflow leaked or reset another endpoint", g, p.stack.Stats().TCP.ResetsSent.Value())
	}
	t.Logf("%d unacknowledged closes at %d/s in bursts of %d; retained cap=%d; peak=%d <= %d bound; drained to zero; retained endpoints survive", burst*rounds, burst*5, burst, retainedCap, peak, bound)
}

func drainClosePackets(p *peer) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for p.link.Read(ctx) != nil {
	}
}

func TestCloseRemovalBeforeReset(t *testing.T) {
	link := &closeWireLink{Link: ns.NewLink()}
	p := newPeerLink(t, false, flows.Defaults(), ns.DefaultOptions(), link.Link, link)
	p.open(1000)
	p.upload([]byte("live"))
	ep := p.endpoint()
	barrier := &closeWireBarrier{flags: header.TCPFlagRst, port: p.port, entered: make(chan struct{}), release: make(chan struct{})}
	unblock := sync.OnceFunc(func() { close(barrier.release) })
	defer unblock()
	link.barrier.Store(barrier)
	done := make(chan struct{})
	go func() { ep.Abort(); close(done) }()
	closeSignal(t, barrier.entered, "reset sent before cleanup")
	if g := p.table.Stats(); g.Flows != 0 {
		t.Error("leave ran after the RST became visible", g)
	}
	unblock()
	closeSignal(t, done, "abort complete")
}
