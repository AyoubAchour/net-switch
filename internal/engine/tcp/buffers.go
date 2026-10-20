package tcp

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

type connection struct {
	id               stack.TransportEndpointID
	done             chan struct{}
	ready            atomic.Pointer[readyRelay]
	ep               tcpip.Endpoint
	ticket           flowapi.Ticket
	up, down         atomic.Uint64
	lastUp, lastDown uint64
	last             time.Time
	clock            tcpip.Clock
	overflowDeadline atomic.Int64
}

// One clock for all flows. Socket limits disable unaccounted autotuning.
// Only the snapshot uses f.mu; endpoint and table work cannot hold up Handle.
func (f *Forwarder) startMaintenance() {
	// Use the stack's clock for both the deadline and the sweep. A single
	// timer does the work off ingress; a manual clock exercises real expiry.
	var mu sync.Mutex
	var timer tcpip.Timer
	mu.Lock()
	timer = f.stack.Clock().AfterFunc(250*time.Millisecond, func() {
		mu.Lock()
		defer mu.Unlock()
		if f.ctx.Err() != nil {
			return
		}
		f.sweep(f.stack.Clock().Now())
		timer.Reset(250 * time.Millisecond)
	})
	mu.Unlock()
	f.wg.Go(func() {
		<-f.ctx.Done()
		mu.Lock()
		timer.Stop()
		mu.Unlock()
		for _, c := range f.connectionSnapshot() {
			c.ticket.Retire()
			if relay := c.ready.Load(); relay != nil {
				relay.cancel()
			}
			c.ep.Abort()
			<-c.done
			c.ticket.Close()
			f.removeConnection(c)
		}
	})
}

func (f *Forwarder) connectionSnapshot() []*connection {
	f.mu.RLock()
	defer f.mu.RUnlock()
	items := make([]*connection, 0, len(f.connections)+len(f.retired))
	for _, c := range f.connections {
		items = append(items, c)
	}
	for c := range f.retired {
		items = append(items, c)
	}
	return items
}

func (f *Forwarder) removeConnection(c *connection) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// A snapshot can outlive a same-tuple replacement. Remove only its owner.
	if f.connections[c.id] == c {
		delete(f.connections, c.id)
	}
	delete(f.retired, c)
}

func (f *Forwarder) sweep(now time.Time) {
	for _, c := range f.connectionSnapshot() {
		state := gtcp.EndpointState(c.ep.State())
		if state == gtcp.StateClose || state == gtcp.StateError {
			c.releaseAdmission()
			select {
			case <-c.done:
				c.ticket.Close()
				f.removeConnection(c)
			default:
			}
			continue
		}
		if state == gtcp.StateLastAck || state == gtcp.StateClosing {
			c.releaseAdmission()
			if deadline := c.overflowDeadline.Load(); deadline != 0 && c.clock.NowMonotonic().Sub(tcpip.MonotonicTime{}) >= time.Duration(deadline) {
				// Recheck state and payload under the endpoint lock. An ACK
				// racing expiry must never reset a cleanly closed endpoint.
				c.ep.(*gtcp.Endpoint).CloseRetained()
			}
		}
		c.resize(now)
	}
}

func (c *connection) resize(now time.Time) {
	b, ok := c.ticket.(interface {
		Grow(int, int) bool
		Shrink(int, int)
	})
	if !ok {
		return
	}
	u, d := c.up.Load(), c.down.Load()
	rx, tx := c.ticket.Buffers()
	if u == c.lastUp && d == c.lastDown {
		if rx == MinimumBuffer && tx == MinimumBuffer {
			return
		}
		if now.Sub(c.last) >= time.Second {
			c.ep.SocketOptions().SetReceiveBufferSize(MinimumBuffer, true)
			c.ep.SocketOptions().SetSendBufferSize(MinimumBuffer, true)
			// Lower limits first, then retain any allocation still held by
			// queued/out-of-order receive segments or unacknowledged sends.
			if ep, ok := c.ep.(interface{ BufferUsage() (int, int) }); ok {
				rxUsed, txUsed := ep.BufferUsage()
				b.Shrink(min(rx, max(MinimumBuffer, rxUsed)), min(tx, max(MinimumBuffer, txUsed)))
			}
		}
		return
	}
	nextRX, nextTX := rx, tx
	if u-c.lastUp >= uint64(rx) {
		nextRX = min(rx*2, 8<<20)
	}
	if d-c.lastDown >= uint64(tx) {
		nextTX = min(tx*2, 6<<20)
	}
	c.last, c.lastUp, c.lastDown = now, u, d
	if (nextRX != rx || nextTX != tx) && b.Grow(nextRX, nextTX) {
		c.ep.SocketOptions().SetReceiveBufferSize(int64(nextRX), true)
		c.ep.SocketOptions().SetSendBufferSize(int64(nextTX), true)
	}
}
