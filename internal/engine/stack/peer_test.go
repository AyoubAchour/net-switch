package stack

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var appAddr = tcpip.AddrFrom4([4]byte{198, 18, 0, 2})
var remoteAddr = tcpip.AddrFrom4([4]byte{203, 0, 113, 7})

type accepted struct {
	conn *gonet.TCPConn
	ep   tcpip.Endpoint
}

// The peer is a wire-level TCP driver, so it can retain and replay exact old
// segments, lose the final ACK and choose overlapping sequence spaces.
type peer struct {
	t                  *testing.T
	link               *channel.Endpoint
	stack              *gv.Stack
	accepted           chan accepted
	dials              atomic.Uint64
	seq, ack, ts, echo uint32
	timestamps         bool
	current            accepted
	syn                []byte
}

func newPeer(t *testing.T, timestamps bool) *peer {
	t.Helper()
	l := channel.New(1024, MTU, "")
	o := DefaultOptions()
	o.TimeWait = 0
	s, err := New(l, o)
	if err != nil {
		t.Fatal(err)
	}
	p := &peer{t: t, link: l, stack: s, timestamps: timestamps, ts: 1000, accepted: make(chan accepted, 8)}
	f := tcp.NewForwarder(s, 1<<20, 16, func(r *tcp.ForwarderRequest) {
		p.dials.Add(1)
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		p.accepted <- accepted{gonet.NewTCPConn(&wq, ep), ep}
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, f.HandlePacket)
	t.Cleanup(func() { s.Close(); s.Wait(); l.Close() })
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
	h.Encode(&header.TCPFields{SrcPort: 40000, DstPort: 443, SeqNum: seq, AckNum: ack, DataOffset: uint8(n), Flags: flags, WindowSize: 65535})
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
	pkt := p.link.ReadContext(ctx)
	if pkt == nil {
		return nil
	}
	v := pkt.ToView()
	b := append([]byte(nil), v.AsSlice()...)
	v.Release()
	pkt.DecRef()
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
	p.t.Helper()
	start := time.Now()
	p.seq, p.ack = seq, 0
	p.ts += 1000
	p.syn = p.packet(p.seq, 0, header.TCPFlagSyn, nil)
	p.inject(p.syn)
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
	// Wait for the asynchronous endpoint removal, not a made-up quiet period.
	deadline := time.Now().Add(time.Second)
	for tcp.EndpointState(p.current.ep.State()) != tcp.StateClose && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if tcp.EndpointState(p.current.ep.State()) != tcp.StateClose {
		p.t.Fatalf("endpoint remained %s", tcp.EndpointState(p.current.ep.State()))
	}
	p.current.conn.Close()
	return fin
}
