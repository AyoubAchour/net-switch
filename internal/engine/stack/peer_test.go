package stack_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

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
	conn *testfake.Conn
}

// The peer is a wire-level TCP driver, so it can retain and replay exact old
// segments, lose the final ACK and choose overlapping sequence spaces.
type peer struct {
	t                  *testing.T
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
}

func newPeer(t *testing.T, timestamps bool) *peer {
	return newPeerOptions(t, timestamps, flows.Defaults(), ns.DefaultOptions())
}

func newPeerOptions(t *testing.T, timestamps bool, limits flows.Limits, options ns.Options) *peer {
	t.Helper()
	l := ns.NewLink()
	s, err := ns.New(l, options)
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
		p.accepted <- accepted{b}
		return a, nil
	}}
	f := ntcp.New(context.Background(), s, limits.Handshakes, table, &testfake.Owners{Value: platform.Owner{AppID: "peer"}}, d, l)
	t.Cleanup(func() { f.Stop(); s.Close(); s.Wait(); f.Wait(); l.Close() })
	return p
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
			p.t.Fatalf("unexpected RST, waiting for %v", flags)
		}
		if h.Flags().Contains(flags) {
			return h
		}
	}
	p.t.Fatalf("timed out waiting for TCP flags %v", flags)
	return nil
}

func (p *peer) open(seq uint32) time.Duration {
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
	if err := p.current.conn.CloseWrite(); err != nil {
		p.t.Fatal(err)
	}
	h := p.wait(header.TCPFlagFin)
	p.ack = h.SequenceNumber() + 1
	p.inject(p.packet(p.seq, p.ack, header.TCPFlagAck, nil))
	fin := p.packet(p.seq, p.ack, header.TCPFlagFin|header.TCPFlagAck, nil)
	p.inject(fin)
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
	return fin
}
