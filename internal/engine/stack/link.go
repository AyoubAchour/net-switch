package stack

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
)

const QueuePackets = 1024

// GC must not evict the output cache precisely when the engine hits its
// memory target. Keep at most one queue plus one writer batch of each size,
// allocate lazily, and release the cache with its link. A link that only
// carries small packets never reserves a queue's worth of MTU-sized storage.
type outputBuffers struct {
	mu                     sync.Mutex
	small                  [QueuePackets + 64]*[256]byte
	large                  [QueuePackets + 64]*[MTU]byte
	smallCount, largeCount int
	closed                 bool
}

// OutputPacket transfers one queue buffer to the TUN writer. Release exactly
// once after the synchronous device write, including error paths. The small
// class keeps a SYN/ACK burst from reserving 9 KiB for every tiny packet.
type OutputPacket struct {
	Bytes   []byte
	storage any
	pool    *outputBuffers
}

func (pool *outputBuffers) packet(size int) OutputPacket {
	if size <= 256 {
		var b *[256]byte
		pool.mu.Lock()
		if pool.smallCount > 0 {
			pool.smallCount--
			b, pool.small[pool.smallCount] = pool.small[pool.smallCount], nil
		}
		pool.mu.Unlock()
		if b == nil {
			b = new([256]byte)
		}
		return OutputPacket{b[:size], b, pool}
	}
	if size <= MTU {
		var b *[MTU]byte
		pool.mu.Lock()
		if pool.largeCount > 0 {
			pool.largeCount--
			b, pool.large[pool.largeCount] = pool.large[pool.largeCount], nil
		}
		pool.mu.Unlock()
		if b == nil {
			b = new([MTU]byte)
		}
		return OutputPacket{b[:size], b, pool}
	}
	return OutputPacket{Bytes: make([]byte, size)}
}

func (p *OutputPacket) Release() {
	if pool := p.pool; pool != nil {
		pool.mu.Lock()
		if !pool.closed {
			switch b := p.storage.(type) {
			case *[256]byte:
				if pool.smallCount < len(pool.small) {
					pool.small[pool.smallCount] = b
					pool.smallCount++
				}
			case *[MTU]byte:
				if pool.largeCount < len(pool.large) {
					pool.large[pool.largeCount] = b
					pool.largeCount++
				}
			}
		}
		pool.mu.Unlock()
	}
	*p = OutputPacket{}
}

func (pool *outputBuffers) close() {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	pool.closed = true
	clear(pool.small[:])
	clear(pool.large[:])
	pool.smallCount, pool.largeCount = 0, 0
}

// Link owns its output buffers. A slot is reserved before copying a packet;
// neither stack writers nor the UDP reply path wait for the TUN consumer.
type Link struct {
	ingress     sync.Mutex
	mu          sync.Mutex
	dispatcher  gv.NetworkDispatcher
	observer    func(*gv.PacketBuffer)
	afterInbound func()
	delivery    atomic.Pointer[linkDelivery]
	queue       [QueuePackets]OutputPacket
	buffers     outputBuffers
	head, count int
	peak        int
	mtu         atomic.Uint32
	closed      bool
	onClose     func()
	ready       chan struct{}
	done        chan struct{}
	Dropped     atomic.Uint64
}

type linkDelivery struct {
	dispatcher gv.NetworkDispatcher
	observer   func(*gv.PacketBuffer)
	afterInbound func()
}

var _ gv.LinkEndpoint = (*Link)(nil)

func NewLink() *Link {
	l := &Link{ready: make(chan struct{}, 1), done: make(chan struct{})}
	l.mtu.Store(MTU)
	return l
}

func (l *Link) enqueue(size int, copyInto func([]byte)) bool {
	l.mu.Lock()
	if l.closed || size > int(l.mtu.Load()) || size <= 0 || l.count == QueuePackets {
		l.Dropped.Add(1)
		l.mu.Unlock()
		return false
	}
	p := l.buffers.packet(size)
	copyInto(p.Bytes)
	l.queue[(l.head+l.count)%QueuePackets] = p
	l.count++
	l.peak = max(l.peak, l.count)
	select {
	case l.ready <- struct{}{}:
	default:
	}
	depth := l.count
	l.mu.Unlock()
	// A TCP processor can emit its entire congestion window without
	// blocking. Give the already-runnable writer a turn before that burst
	// exhausts the queue. This never waits for queue space: a stalled writer
	// still reaches the same cap and excess packets are still dropped.
	if depth >= QueuePackets/2 && depth%64 == 0 {
		runtime.Gosched()
	}
	return true
}

func (l *Link) Send(p []byte) bool {
	return l.enqueue(len(p), func(dst []byte) { copy(dst, p) })
}

func (l *Link) WritePackets(pkts gv.PacketBufferList) (int, tcpip.Error) {
	for _, p := range pkts.AsSlice() {
		l.enqueue(p.Size(), func(dst []byte) {
			views, skip := p.AsViewList()
			for view := views.Front(); view != nil; view = view.Next() {
				part := view.AsSlice()
				if skip >= len(part) {
					skip -= len(part)
					continue
				}
				part, skip = part[skip:], 0
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
			l.queue[l.head] = OutputPacket{}
			l.head = (l.head + 1) % QueuePackets
			l.count--
			l.mu.Unlock()
			// This compatibility API gives callers indefinitely owned bytes.
			// Production uses ReadOwnedBatch to avoid the extra allocation.
			data := append([]byte(nil), p.Bytes...)
			p.Release()
			return data
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
	var local [64]OutputPacket
	owned := local[:min(len(packets), len(local))]
	if len(packets) > len(local) {
		owned = make([]OutputPacket, min(len(packets), QueuePackets))
	}
	n := l.ReadOwnedBatch(ctx, owned)
	// Compatibility callers receive independent bytes. Allocate/copy after
	// releasing the queue lock, so a GC assist cannot block every producer.
	for i := range n {
		packets[i] = append([]byte(nil), owned[i].Bytes...)
		owned[i].Release()
	}
	return n
}

func (l *Link) ReadOwnedBatch(ctx context.Context, packets []OutputPacket) int {
	return l.readBatch(ctx, len(packets), func(i int, p OutputPacket) { packets[i] = p })
}

func (l *Link) readBatch(ctx context.Context, capacity int, consume func(int, OutputPacket)) int {
	if capacity == 0 {
		return 0
	}
	for {
		l.mu.Lock()
		if l.count != 0 {
			n := min(capacity, l.count)
			for i := 0; i < n; i++ {
				consume(i, l.queue[l.head])
				l.queue[l.head] = OutputPacket{}
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
	view := l.delivery.Load()
	if view != nil && view.dispatcher != nil {
		if view.observer != nil {
			view.observer(p)
		}
		view.dispatcher.DeliverNetworkPacket(protocol, p)
		if view.afterInbound != nil {
			view.afterInbound()
		}
	}
}

// SetAfterInbound installs the close-processing fence before ingress starts.
// It runs after demux locks are released, under the single ingress owner.
func (l *Link) SetAfterInbound(after func()) {
	l.mu.Lock()
	l.afterInbound = after
	if !l.closed {
		l.delivery.Store(&linkDelivery{l.dispatcher, l.observer, after})
	}
	l.mu.Unlock()
}

func (l *Link) SetObserver(observe func(*gv.PacketBuffer)) {
	l.mu.Lock()
	l.observer = observe
	if !l.closed {
		l.delivery.Store(&linkDelivery{l.dispatcher, observe, l.afterInbound})
	}
	l.mu.Unlock()
}

func (l *Link) Queued() int     { l.mu.Lock(); defer l.mu.Unlock(); return l.count }
func (l *Link) PeakQueued() int { l.mu.Lock(); defer l.mu.Unlock(); return l.peak }

func (l *Link) Close() {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	l.dispatcher = nil
	l.delivery.Store(nil)
	for i := range l.queue {
		l.queue[i].Release()
	}
	l.buffers.close()
	l.count = 0
	close(l.done)
	f := l.onClose
	l.mu.Unlock()
	if f != nil {
		f()
	}
}

func (l *Link) Attach(d gv.NetworkDispatcher) {
	l.mu.Lock()
	l.dispatcher = d
	if !l.closed {
		l.delivery.Store(&linkDelivery{d, l.observer, l.afterInbound})
	}
	l.mu.Unlock()
}
func (l *Link) IsAttached() bool                        { v := l.delivery.Load(); return v != nil && v.dispatcher != nil }
func (l *Link) MTU() uint32                             { return l.mtu.Load() }
func (l *Link) SetMTU(n uint32)                         { l.mtu.Store(n) }
func (l *Link) SetOnCloseAction(f func())               { l.mu.Lock(); l.onClose = f; l.mu.Unlock() }
func (*Link) MaxHeaderLength() uint16                   { return 0 }
func (*Link) LinkAddress() tcpip.LinkAddress            { return "" }
func (*Link) SetLinkAddress(tcpip.LinkAddress)          {}
func (*Link) Capabilities() gv.LinkEndpointCapabilities { return 0 }
func (*Link) Wait()                                     {}
func (*Link) ARPHardwareType() header.ARPHardwareType   { return header.ARPHardwareNone }
func (*Link) AddHeader(*gv.PacketBuffer)                {}
func (*Link) ParseHeader(*gv.PacketBuffer) bool         { return true }
