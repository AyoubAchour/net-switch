package stack

import (
	"context"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func TestLinkQueue(t *testing.T) {
	l := NewLink()
	defer l.Close()
	p := []byte{42}
	for range QueuePackets {
		if !l.Send(p) {
			t.Fatal("early drop")
		}
	}
	p[0] = 99
	if l.Send(p) || l.Dropped.Load() != 1 {
		t.Fatal("full queue did not drop")
	}
	for range QueuePackets {
		if got := l.Read(context.Background()); len(got) != 1 || got[0] != 42 {
			t.Fatal("borrowed buffer retained")
		}
	}
	if l.Send(make([]byte, MTU+1)) {
		t.Fatal("oversize accepted")
	}
	l.Close()
	if l.Send(p) || l.Read(context.Background()) != nil {
		t.Fatal("closed queue active")
	}
}

type orderDispatcher struct {
	seen map[uint32]uint32
	t    *testing.T
}

func (d *orderDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *gv.PacketBuffer) {}
func (d *orderDispatcher) DeliverNetworkPacket(_ tcpip.NetworkProtocolNumber, p *gv.PacketBuffer) {
	b := p.Data().AsRange().ToSlice()
	tuple, seq := binary.BigEndian.Uint32(b), binary.BigEndian.Uint32(b[4:])
	if d.seen[tuple] != seq {
		d.t.Errorf("tuple %d: got %d, want %d", tuple, seq, d.seen[tuple])
	}
	d.seen[tuple]++
}
func TestPacketOrderPerTupleThroughLink(t *testing.T) {
	l := NewLink()
	defer l.Close()
	d := &orderDispatcher{seen: map[uint32]uint32{}, t: t}
	l.Attach(d)
	var wg sync.WaitGroup
	for key := range uint32(8) {
		wg.Go(func() {
			for batch := range uint32(100) {
				var packets []*gv.PacketBuffer
				for i := range uint32(16) {
					b := make([]byte, 8)
					binary.BigEndian.PutUint32(b, key)
					binary.BigEndian.PutUint32(b[4:], batch*16+i)
					packets = append(packets, gv.NewPacketBuffer(gv.PacketBufferOptions{Payload: buffer.MakeWithData(b)}))
				}
				l.InjectBatch(0, packets)
				for _, p := range packets {
					p.DecRef()
				}
			}
		})
	}
	wg.Wait()
	for key := range uint32(8) {
		if d.seen[key] != 1600 {
			t.Fatal("packets lost")
		}
	}
	t.Log("12800 packets, eight tuple shards, 16-segment batches: per-tuple order preserved")
}

func TestLinkConcurrentClose(t *testing.T) {
	l := NewLink()
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			for range 200 {
				l.Send([]byte{1})
			}
		})
	}
	wg.Go(l.Close)
	wg.Wait()
}

func TestInboundAndMTUDoNotWaitForOutputCopy(t *testing.T) {
	l := NewLink()
	dispatcher := &orderDispatcher{seen: map[uint32]uint32{}, t: t}
	l.Attach(dispatcher)
	observed := false
	l.SetObserver(func(*gv.PacketBuffer) { observed = true })
	copying, resume, written := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		l.enqueue(1, packetOther, false, func(dst []byte) { close(copying); <-resume; dst[0] = 7 })
		close(written)
	}()
	defer func() { close(resume); <-written; l.Close() }()
	<-copying
	done := make(chan bool, 1)
	go func() {
		ok := l.MTU() == MTU && l.IsAttached()
		p := gv.NewPacketBuffer(gv.PacketBufferOptions{Payload: buffer.MakeWithData(make([]byte, 8))})
		l.InjectInbound(0, p)
		p.DecRef()
		done <- ok
	}()
	select {
	case ok := <-done:
		if !ok || !observed || dispatcher.seen[0] != 1 {
			t.Fatal("inbound snapshot lost state or delivery")
		}
	case <-time.After(time.Second):
		t.Fatal("inbound delivery or MTU waited for an output copy")
	}
}

func TestStackOptions(t *testing.T) {
	o := DefaultOptions()
	o.ClockResolution = 500 * time.Microsecond
	s, err := New(NewLink(), o)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Wait()
	defer s.Close()
	var cc tcpip.CongestionControlOption
	var tw tcpip.TCPTimeWaitTimeoutOption
	var rx tcpip.TCPReceiveBufferSizeRangeOption
	var tx tcpip.TCPSendBufferSizeRangeOption
	for _, opt := range []tcpip.GettableTransportProtocolOption{&cc, &tw, &rx, &tx} {
		if err := s.TransportProtocolOption(tcp.ProtocolNumber, opt); err != nil {
			t.Fatal(err)
		}
	}
	if cc != "cubic" || time.Duration(tw) != o.TimeWait || rx.Default != 64<<10 || rx.Max != 8<<20 || tx.Default != 64<<10 || tx.Max != 6<<20 || s.ClockResolution() != o.ClockResolution {
		t.Fatalf("options: %s %v %+v %+v %s", cc, tw, rx, tx, s.ClockResolution())
	}
}
