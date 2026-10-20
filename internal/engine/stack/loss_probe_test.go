package stack_test

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func sackSYN(b []byte) []byte {
	// Advertise 1460-byte segments and selective acknowledgements.
	options := []byte{2, 4, 5, 180, 4, 2, 1, 1}
	result := append(bytes.Clone(b), options...)
	ip := header.IPv4(result)
	binary.BigEndian.PutUint16(result[2:4], uint16(len(result)))
	ip.SetChecksum(0)
	ip.SetChecksum(^ip.CalculateChecksum())
	h := header.TCP(result[ip.HeaderLength():])
	h[12] = byte(len(h)/4) << 4
	h.SetChecksum(0)
	sum := header.PseudoHeaderChecksum(tcp.ProtocolNumber, ip.SourceAddress(), ip.DestinationAddress(), uint16(len(h)))
	h.SetChecksum(^checksum.Checksum(h, sum))
	return result
}

func TestTCPRecoveryAfterLostWindow(t *testing.T) {
	for _, mode := range []string{"rack", "sack"} {
		t.Run(mode, func(t *testing.T) { tcpRecoveryAfterLostWindow(t, mode) })
	}
}

func tcpRecoveryAfterLostWindow(t *testing.T, mode string) {
	clock := faketime.NewManualClock()
	options := ns.DefaultOptions()
	options.Clock = clock
	options.ClockResolution = 0
	p := newPeerOptions(t, false, flows.Defaults(), options)
	if mode == "sack" {
		recovery := tcpip.TCPRecovery(0)
		if err := p.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &recovery); err != nil {
			t.Fatal(err)
		}
	}
	p.fixedSendBuffer = 64 << 10
	p.openWith(1000, func(b []byte) {
		p.inject(sackSYN(b))
	})
	p.upload([]byte("download"))
	ep := p.endpoint()
	if !ep.SACKPermitted {
		t.Fatal("SACK was not negotiated")
	}
	const mss, segments = 1460, 16
	payload := make([]byte, mss*segments)
	for i := range payload {
		payload[i] = byte(i*17 + i/251)
	}
	written := make(chan error, 1)
	go func() {
		_, err := p.current.conn.Write(payload)
		written <- err
	}()
	awaitSendBuffer(t, ep, len(payload))
	if err := <-written; err != nil {
		t.Fatal(err)
	}

	// Lose the complete initial congestion window, including any tail probe.
	// There is no random loss, packet delay or scheduling-dependent injection.
	lost := 0
	for lost < tcp.InitialCwnd {
		h := p.read(time.Second)
		if h == nil {
			t.Fatalf("initial flight stopped after %d packets", lost)
		}
		if data := h[h.DataOffset():]; len(data) != 0 {
			if h.SequenceNumber() != p.ack+uint32(lost*mss) || len(data) != mss {
				t.Fatal("unexpected initial flight", segmentDescription(h))
			}
			lost++
		}
	}
	var first header.TCP
	for attempt := 0; attempt < 4; attempt++ {
		var info tcpip.TCPInfoOption
		if err := ep.GetSockOpt(&info); err != nil {
			t.Fatal(err)
		}
		clock.Advance(info.RTO + time.Millisecond)
		h := p.read(time.Second)
		if h == nil {
			t.Fatal("loss timer did not send a packet")
		}
		if p.stack.Stats().TCP.Timeouts.Value() != 0 && h.SequenceNumber() == p.ack {
			first = h
			break
		}
	}
	if first == nil {
		t.Fatal("did not establish an RTO retransmission")
	}
	t.Logf("lost %d packets; RTO retransmitted %s", lost, segmentDescription(first))

	// ACK every retransmission. Advancing only by 1 ms per ACK leaves the next
	// RTO unexpired: progress must come from ACK handling, not another timeout.
	received := make([]byte, 0, len(payload))
	h := first
	for len(received) < len(payload) {
		data := h[h.DataOffset():]
		if h.SequenceNumber() == p.ack && len(data) != 0 {
			received = append(received, data...)
			p.ack += uint32(len(data))
		}
		clock.Advance(time.Millisecond)
		p.inject(p.packet(p.seq, p.ack, header.TCPFlagAck, nil))
		if len(received) == len(payload) {
			break
		}
		h = p.read(time.Second)
		if h == nil {
			var info tcpip.TCPInfoOption
			ep.GetSockOpt(&info)
			t.Fatalf("ACK-driven recovery stalled at %d/%d bytes: TCP=%+v timeouts=%d", len(received), len(payload), info, p.stack.Stats().TCP.Timeouts.Value())
		}
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("recovered payload changed")
	}
	if got := p.stack.Stats().TCP.Timeouts.Value(); got != 1 {
		t.Fatalf("needed %d retransmission timeouts to recover one lost window", got)
	}
}
