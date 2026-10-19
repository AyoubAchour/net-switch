package stack

import (
	"context"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
)

const QueuePackets = 1024

// Link owns its output buffers. A slot is reserved before copying a packet;
// neither stack writers nor the UDP reply path wait for the TUN consumer.
type Link struct {
	ingress     sync.Mutex
	mu          sync.Mutex
	dispatcher  gv.NetworkDispatcher
	observer    func(*gv.PacketBuffer)
	queue       [QueuePackets][]byte
	head, count int
	mtu         uint32
	closed      bool
	onClose     func()
	ready       chan struct{}
	done        chan struct{}
	Dropped     atomic.Uint64
}

var _ gv.LinkEndpoint = (*Link)(nil)

func NewLink() *Link {
	return &Link{mtu: MTU, ready: make(chan struct{}, 1), done: make(chan struct{})}
}

func (l *Link) enqueue(size int, copyInto func([]byte)) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || size > int(l.mtu) || size <= 0 || l.count == QueuePackets {
		l.Dropped.Add(1)
		return false
	}
	p := make([]byte, size)
	copyInto(p)
	l.queue[(l.head+l.count)%QueuePackets] = p
	l.count++
	select {
	case l.ready <- struct{}{}:
	default:
	}
	return true
}

func (l *Link) Send(p []byte) bool {
	return l.enqueue(len(p), func(dst []byte) { copy(dst, p) })
}

func (l *Link) WritePackets(pkts gv.PacketBufferList) (int, tcpip.Error) {
	for _, p := range pkts.AsSlice() {
		l.enqueue(p.Size(), func(dst []byte) {
			for _, part := range p.AsSlices() {
				dst = dst[copy(dst, part):]
			}
		})
	}
	// Dropping at this boundary models link loss; TCP handles retransmission.
	return pkts.Len(), nil
}

func (l *Link) Read(ctx context.Context) []byte {
	for {
		l.mu.Lock()
		if l.count != 0 {
			p := l.queue[l.head]
			l.queue[l.head] = nil
			l.head = (l.head + 1) % QueuePackets
			l.count--
			l.mu.Unlock()
			return p
		}
		closed := l.closed
		l.mu.Unlock()
		if closed {
			return nil
		}
		select {
		case <-l.ready:
		case <-l.done:
			return nil
		case <-ctx.Done():
			return nil
		}
	}
}

// ReadBatch waits for the first packet, then drains the packets already queued
// in FIFO order. It never waits to fill a batch. The TUN writer can publish one
// batch with one driver wake-up without delaying a lone packet.
func (l *Link) ReadBatch(ctx context.Context, packets [][]byte) int {
	if len(packets) == 0 {
		return 0
	}
	for {
		l.mu.Lock()
		if l.count != 0 {
			n := min(len(packets), l.count)
			for i := 0; i < n; i++ {
				packets[i] = l.queue[l.head]
				l.queue[l.head] = nil
				l.head = (l.head + 1) % QueuePackets
			}
			l.count -= n
			l.mu.Unlock()
			return n
		}
		closed := l.closed
		l.mu.Unlock()
		if closed {
			return 0
		}
		select {
		case <-l.ready:
		case <-l.done:
			return 0
		case <-ctx.Done():
			return 0
		}
	}
}

func (l *Link) InjectInbound(protocol tcpip.NetworkProtocolNumber, p *gv.PacketBuffer) {
	l.ingress.Lock()
	defer l.ingress.Unlock()
	l.deliver(protocol, p)
}

// InjectBatch preserves GSO segment order and keeps other producers from
// interleaving a batch. The engine owns one TUN reader; no multi-queue TUN.
func (l *Link) InjectBatch(protocol tcpip.NetworkProtocolNumber, packets []*gv.PacketBuffer) {
	l.ingress.Lock()
	defer l.ingress.Unlock()
	for _, p := range packets {
		l.deliver(protocol, p)
	}
}

func (l *Link) deliver(protocol tcpip.NetworkProtocolNumber, p *gv.PacketBuffer) {
	l.mu.Lock()
	d := l.dispatcher
	observe := l.observer
	closed := l.closed
	l.mu.Unlock()
	if !closed && d != nil {
		if observe != nil {
			observe(p)
		}
		d.DeliverNetworkPacket(protocol, p)
	}
}

func (l *Link) SetObserver(observe func(*gv.PacketBuffer)) {
	l.mu.Lock()
	l.observer = observe
	l.mu.Unlock()
}

func (l *Link) Close() {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	l.dispatcher = nil
	l.queue = [QueuePackets][]byte{}
	l.count = 0
	close(l.done)
	f := l.onClose
	l.mu.Unlock()
	if f != nil {
		f()
	}
}

func (l *Link) Attach(d gv.NetworkDispatcher)           { l.mu.Lock(); l.dispatcher = d; l.mu.Unlock() }
func (l *Link) IsAttached() bool                        { l.mu.Lock(); defer l.mu.Unlock(); return l.dispatcher != nil }
func (l *Link) MTU() uint32                             { l.mu.Lock(); defer l.mu.Unlock(); return l.mtu }
func (l *Link) SetMTU(n uint32)                         { l.mu.Lock(); l.mtu = n; l.mu.Unlock() }
func (l *Link) SetOnCloseAction(f func())               { l.mu.Lock(); l.onClose = f; l.mu.Unlock() }
func (*Link) MaxHeaderLength() uint16                   { return 0 }
func (*Link) LinkAddress() tcpip.LinkAddress            { return "" }
func (*Link) SetLinkAddress(tcpip.LinkAddress)          {}
func (*Link) Capabilities() gv.LinkEndpointCapabilities { return 0 }
func (*Link) Wait()                                     {}
func (*Link) ARPHardwareType() header.ARPHardwareType   { return header.ARPHardwareNone }
func (*Link) AddHeader(*gv.PacketBuffer)                {}
func (*Link) ParseHeader(*gv.PacketBuffer) bool         { return true }
