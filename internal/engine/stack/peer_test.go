package stack_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	ntcp "github.com/AyoubAchour/net-switch/internal/engine/tcp"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

var appAddr = tcpip.AddrFrom4([4]byte{198, 18, 0, 2})
var remoteAddr = tcpip.AddrFrom4([4]byte{203, 0, 113, 7})

type accepted struct {
	conn         *testfake.Conn
	relayClosed  <-chan struct{}
	sentEOF      <-chan struct{}
	closeEntered <-chan struct{}
}

type observedRemote struct {
	*testfake.Conn
	closed       chan struct{}
	once         sync.Once
	closeGate    *atomic.Pointer[chan struct{}]
	sentEOF      chan struct{}
	eofOnce      sync.Once
	readEOF      atomic.Bool
	closeEntered chan struct{}
	enterOnce    sync.Once
}

func (c *observedRemote) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err == io.EOF {
		c.readEOF.Store(true)
	}
	return n, err
}

func (c *observedRemote) CloseRead() error {
	err := c.Conn.CloseRead()
	c.eofOnce.Do(func() { close(c.sentEOF) })
	// Hold the copy goroutine after CloseWrite but before Splice can return.
	// Blocking only remote.Close is too late: c.done may already be closed,
	// allowing the monitor to release the ticket during a negative test.
	if gate := c.closeGate.Load(); gate != nil && c.readEOF.Load() {
		<-*gate
	}
	return err
}

func (c *observedRemote) Close() error {
	c.enterOnce.Do(func() { close(c.closeEntered) })
	if gate := c.closeGate.Load(); gate != nil {
		<-*gate
	}
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

// The peer is a wire-level TCP driver, so it can retain and replay exact old
// segments, lose the final ACK and choose overlapping sequence spaces.
type peer struct {
	t                  testing.TB
	link               *ns.Link
	stack              *gv.Stack
	accepted           chan accepted
	dials              atomic.Uint64
	seq, ack, ts, echo uint32
	timestamps         bool
	current            accepted
	syn                []byte
	table              *flows.Table
	config             policy.Config
	port               uint16
	forward            *ntcp.Forwarder
	phase              string
	lastSent           []byte
	owners             *testfake.Owners
	relayCloseGate     atomic.Pointer[chan struct{}]
	fixedSendBuffer    int
	setupGate          <-chan struct{}
	setupEntered       chan struct{}
}

type peerControl struct {
	*flows.Table
	peer *peer
}

func (c peerControl) Begin(proto string, tuple platform.Tuple) (flowapi.Ticket, error) {
	ticket, err := c.Table.Begin(proto, tuple)
	if err != nil {
		return ticket, err
	}
	if c.peer.fixedSendBuffer != 0 {
		ticket = &fixedBufferTicket{Ticket: ticket, send: c.peer.fixedSendBuffer}
	}
	if c.peer.setupGate != nil {
		ticket = &setupBufferTicket{Ticket: ticket, gate: c.peer.setupGate, entered: c.peer.setupEntered}
	}
	return ticket, nil
}

type setupBufferTicket struct {
	flowapi.Ticket
	gate    <-chan struct{}
	entered chan<- struct{}
}

func (t *setupBufferTicket) Buffers() (int, int) {
	t.entered <- struct{}{}
	<-t.gate
	return t.Ticket.Buffers()
}

// Reserve the benchmark's fixed buffer, then hide Grow/Shrink from the monitor
// so it cannot resize the deliberately queued tail while the window is zero.
type fixedBufferTicket struct {
	flowapi.Ticket
	send int
}

func (t *fixedBufferTicket) Resolve(owner platform.Owner) (flowapi.Decision, error) {
	d, err := t.Ticket.Resolve(owner)
	if err == nil && !t.Ticket.(interface{ Grow(int, int) bool }).Grow(64<<10, t.send) {
		return d, flows.ErrBudget
	}
	return d, err
}

func newPeer(t testing.TB, timestamps bool) *peer {
	return newPeerOptions(t, timestamps, flows.Defaults(), ns.DefaultOptions())
}

func newPeerOptions(t testing.TB, timestamps bool, limits flows.Limits, options ns.Options) *peer {
	t.Helper()
	l := ns.NewLink()
	return newPeerLink(t, timestamps, limits, options, l, l)
}

func newPeerLink(t testing.TB, timestamps bool, limits flows.Limits, options ns.Options, l *ns.Link, endpoint ns.OrderedLink) *peer {
	t.Helper()
	s, err := ns.New(endpoint, options)
	if err != nil {
		t.Fatal(err)
	}
	table := flows.New(limits, nil)
	config := policy.Config{Lines: []platform.Line{{ID: "A"}, {ID: "B"}}, AppLines: map[string]string{"peer": "B"}, IPv6: true}
	if _, err := table.Apply(policy.Revision{N: 1, Hash: policy.Hash(config), Config: config}); err != nil {
		t.Fatal(err)
	}
	p := &peer{t: t, link: l, stack: s, table: table, config: config, port: 40000, timestamps: timestamps, ts: 1000, accepted: make(chan accepted, 8)}
	d := testfake.Dialer{TCPFunc: func(context.Context, string, netip.AddrPort) (platform.TCPConn, error) {
		p.dials.Add(1)
		a, b := testfake.Pair()
		closed := make(chan struct{})
		eof := make(chan struct{})
		entered := make(chan struct{})
		p.accepted <- accepted{conn: b, relayClosed: closed, sentEOF: eof, closeEntered: entered}
		return &observedRemote{Conn: a, closed: closed, closeGate: &p.relayCloseGate, sentEOF: eof, closeEntered: entered}, nil
	}}
	p.owners = &testfake.Owners{Value: platform.Owner{AppID: "peer"}}
	f := ntcp.New(context.Background(), s, limits.Handshakes, peerControl{Table: table, peer: p}, p.owners, d, l)
	p.forward = f
	t.Cleanup(func() { f.Stop(); s.Close(); s.Wait(); f.Wait(); l.Close() })
	return p
}

func (p *peer) holdRelayCleanup() func() {
	gate := make(chan struct{})
	p.relayCloseGate.Store(&gate)
	return sync.OnceFunc(func() { p.relayCloseGate.Store(nil); close(gate) })
}

func (p *peer) packet(seq, ack uint32, flags header.TCPFlags, payload []byte) []byte {
	n := header.TCPMinimumSize
	if p.timestamps {
		n += 12
	}
	b := make([]byte, header.IPv4MinimumSize+n+len(payload))
	ip := header.IPv4(b)
	ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(b)), TTL: 64, Protocol: uint8(tcp.ProtocolNumber), SrcAddr: appAddr, DstAddr: remoteAddr})
	ip.SetChecksum(^ip.CalculateChecksum())
	h := header.TCP(b[header.IPv4MinimumSize:])
	h.Encode(&header.TCPFields{SrcPort: p.port, DstPort: 443, SeqNum: seq, AckNum: ack, DataOffset: uint8(n), Flags: flags, WindowSize: 65535})
	if p.timestamps {
		copy(h[20:], []byte{1, 1, 8, 10})
		binary.BigEndian.PutUint32(h[24:], p.ts)
		binary.BigEndian.PutUint32(h[28:], p.echo)
	}
	copy(h[n:], payload)
	partial := header.PseudoHeaderChecksum(tcp.ProtocolNumber, appAddr, remoteAddr, uint16(len(h)))
	h.SetChecksum(^checksum.Checksum(h, partial))
	return b
}

func (p *peer) inject(b []byte) {
	p.lastSent = b
	p.deliver(b)
}

func (p *peer) deliver(b []byte) {
	pkt := gv.NewPacketBuffer(gv.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
	p.link.InjectInbound(ipv4.ProtocolNumber, pkt)
	pkt.DecRef()
}

func (p *peer) read(timeout time.Duration) header.TCP {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	b := p.link.Read(ctx)
	if b == nil {
		return nil
	}
	ip := header.IPv4(b)
	h := header.TCP(b[ip.HeaderLength():])
	if len(h) < header.TCPMinimumSize || int(h.DataOffset()) > len(h) {
		p.t.Fatal("bad TCP reply")
	}
	if !h.IsChecksumValid(ip.SourceAddress(), ip.DestinationAddress(), checksum.Checksum(h[h.DataOffset():], 0), uint16(len(h))-uint16(h.DataOffset())) {
		p.t.Fatal("invalid reply checksum")
	}
	if p.timestamps {
		p.echo = h.ParsedOptions().TSVal
	}
	return h
}

func (p *peer) wait(flags header.TCPFlags) header.TCP {
	p.t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		h := p.read(time.Until(deadline))
		if h == nil {
			break
		}
		if h.Flags().Contains(header.TCPFlagRst) {
			p.t.Fatalf("unexpected RST, waiting for %v; reply=%s; %s", flags, segmentDescription(h), p.diagnostics())
		}
		if h.DestinationPort() != p.port {
			continue // Old close traffic is harmless, but its resets are not.
		}
		if h.Flags().Contains(flags) {
			return h
		}
	}
	p.t.Fatalf("timed out waiting for TCP flags %v; %s", flags, p.diagnostics())
	return nil
}

func segmentDescription(h header.TCP) string {
	return fmt.Sprintf("%d->%d flags=%v seq=%d ack=%d data=%d", h.SourcePort(), h.DestinationPort(), h.Flags(), h.SequenceNumber(), h.AckNumber(), len(h)-int(h.DataOffset()))
}

func (p *peer) diagnostics() string {
	states := make(map[uint16]string)
	for _, port := range []uint16{p.port - 1, p.port, p.port + 1} {
		id := gv.TransportEndpointID{LocalAddress: remoteAddr, LocalPort: 443, RemoteAddress: appAddr, RemotePort: port}
		states[port] = "unregistered"
		if ep, ok := p.stack.FindTransportEndpoint(header.IPv4ProtocolNumber, tcp.ProtocolNumber, id, ns.NIC).(*tcp.Endpoint); ok {
			states[port] = tcp.EndpointState(ep.State()).String()
		}
	}
	last := "none"
	if p.lastSent != nil {
		ip := header.IPv4(p.lastSent)
		last = segmentDescription(header.TCP(p.lastSent[ip.HeaderLength():]))
	}
	return fmt.Sprintf("phase=%q port=%d peer seq=%d ack=%d last sent=%s states=%v table=%+v dials=%d forward rejected=%d invalid=%d dial failed=%d stack resets=%d", p.phase, p.port, p.seq, p.ack, last, states, p.table.Stats(), p.dials.Load(), p.forward.Rejected.Load(), p.forward.Invalid.Load(), p.forward.DialFailed.Load(), p.stack.Stats().TCP.ResetsSent.Value())
}

func (p *peer) open(seq uint32) time.Duration {
	p.t.Helper()
	return p.openWith(seq, p.inject)
}

func (p *peer) openWith(seq uint32, inject func([]byte)) time.Duration {
	p.t.Helper()
	start := time.Now()
	p.seq, p.ack = seq, 0
	p.ts += 1000
	p.syn = p.packet(p.seq, 0, header.TCPFlagSyn, nil)
	inject(p.syn)
	h := p.wait(header.TCPFlagSyn | header.TCPFlagAck)
	p.ack = h.SequenceNumber() + 1
	p.seq++
	p.inject(p.packet(p.seq, p.ack, header.TCPFlagAck, nil))
	select {
	case p.current = <-p.accepted:
	case <-time.After(2 * time.Second):
		p.t.Fatal("handshake did not finish")
	}
	if err := p.current.conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		p.t.Fatal(err)
	}
	return time.Since(start)
}

func (p *peer) upload(payload []byte) []byte {
	p.t.Helper()
	b := p.packet(p.seq, p.ack, header.TCPFlagAck|header.TCPFlagPsh, payload)
	p.inject(b)
	p.seq += uint32(len(payload))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(p.current.conn, got); err != nil {
		p.t.Fatal(err)
	}
	if sha256.Sum256(payload) != sha256.Sum256(got) {
		p.t.Fatal("payload corruption")
	}
	return b
}

func (p *peer) closeActive() []byte {
	p.t.Helper()
	fin, delivered := p.closeActiveWire()
	<-delivered
	return fin
}

// closeActiveWire exposes the ACK boundary independently of ingress completion.
// Only a test deliberately holding the output writer should leave it unfenced;
// timer tests must finish ingress before advancing the clock or arming cleanup.
func (p *peer) closeActiveWire() ([]byte, <-chan struct{}) {
	p.t.Helper()
	if err := p.current.conn.CloseWrite(); err != nil {
		p.t.Fatal(err)
	}
	h := p.wait(header.TCPFlagFin)
	p.ack = h.SequenceNumber() + 1
	p.inject(p.packet(p.seq, p.ack, header.TCPFlagAck, nil))
	fin := p.packet(p.seq, p.ack, header.TCPFlagFin|header.TCPFlagAck, nil)
	// A wire ACK can be visible while ingress is still completing the FIN.
	// Let barrier tests observe that boundary without sharing peer state.
	p.lastSent = fin
	delivered := make(chan struct{})
	go func() { p.deliver(fin); close(delivered) }()
	p.seq++
	for {
		h = p.wait(header.TCPFlagAck)
		if h.AckNumber() == p.seq {
			break
		}
	}
	// Immediately reuse after the wire ACK. Never wait for StateClose or for
	// endpoint removal; TIME_WAIT must still protect lost final ACKs.
	p.current.conn.Close()
	return fin, delivered
}
