package tcp

import (
	"sync/atomic"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"gvisor.dev/gvisor/pkg/tcpip"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

type connection struct {
	done             chan struct{}
	ep               tcpip.Endpoint
	ticket           flowapi.Ticket
	up, down         atomic.Uint64
	lastUp, lastDown uint64
	last             time.Time
}

// One clock for all flows. Socket limits disable unaccounted autotuning.
// Reservations survive the relay and are released only after endpoint removal.
func (f *Forwarder) maintain() {
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	defer func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		for id, c := range f.connections {
			c.ep.Abort()
			<-c.done
			c.ticket.Close()
			delete(f.connections, id)
		}
	}()
	for {
		select {
		case <-f.ctx.Done():
			return
		case now := <-tick.C:
			f.mu.Lock()
			for id, c := range f.connections {
				state := gtcp.EndpointState(c.ep.State())
				if state == gtcp.StateClose || state == gtcp.StateError {
					select {
					case <-c.done:
						c.ticket.Close()
						delete(f.connections, id)
					default:
					}
					continue
				}
				if state == gtcp.StateTimeWait {
					if t, ok := c.ticket.(interface{ TimeWait() }); ok {
						t.TimeWait()
					}
				}
				c.resize(now)
			}
			f.mu.Unlock()
		}
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
