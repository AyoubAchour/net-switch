package tcp

import (
	"sync"
	"sync/atomic"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

type pendingOpen struct {
	ticket    flowapi.Ticket
	request   *gtcp.ForwarderRequest // published under f.mu before endpoint creation
	once      sync.Once
	completed atomic.Bool
	hungUp    atomic.Bool // endpoint-specific notification, never inferred from a reused tuple
}

func (f *Forwarder) complete(id stack.TransportEndpointID, p *pendingOpen, reset bool) {
	p.once.Do(func() {
		// CreateEndpoint holds the request lock until the handshake wakes.
		// Complete waits only for that return, never for dial/relay cleanup.
		// Do not hold f.mu: handshake cleanup can hand a queued SYN back to us.
		p.request.Complete(reset)
		f.mu.Lock()
		if f.pending[id] == p {
			delete(f.pending, id)
		}
		f.mu.Unlock()
		p.completed.Store(true)
	})
}

// finishClose runs after the ordered ingress fence, with no gVisor locks held.
func (f *Forwarder) finishClose(ep *gtcp.Endpoint) {
	if !closeAdmissionEnabled {
		return
	}
	id := ep.TransportEndpointInfo.ID
	f.mu.Lock()
	c, p := f.connections[id], f.pending[id]
	f.mu.Unlock()
	if c != nil && c.ep == ep {
		c.releaseAdmission()
	}
	if p != nil && p.hungUp.Load() && closedState(ep) {
		p.ticket.Retire()
		// Release both gates before ingress can admit another SYN. open may
		// still be blocked closing the remote or finishing other deferred work.
		f.complete(id, p, false)
	}
}

func closedState(ep interface{ State() uint32 }) bool {
	state := gtcp.EndpointState(ep.State())
	return state == gtcp.StateClose || state == gtcp.StateError
}

// Timer closes have no ingress packet. Reclaim them before a capacity decision,
// including per-owner resolution, without scanning all flows for every SYN.
func (f *Forwarder) reclaimAtCapacity(owner *platform.Owner) {
	if c, ok := f.control.(interface{ AtCapacity(*platform.Owner) bool }); ok && c.AtCapacity(owner) {
		for _, c := range f.connectionSnapshot() {
			c.releaseAdmission()
		}
	}
}

// After both directions end, queued or retransmittable payload still consumes
// a live slot. A FIN by itself consumes the bounded retained-endpoint budget.
func (c *connection) releaseAdmission() {
	if !closeAdmissionEnabled {
		return
	}
	state := gtcp.EndpointState(c.ep.State())
	switch state {
	case gtcp.StateClose, gtcp.StateError:
		c.ticket.Retire()
		c.ticket.EndTimeWait()
	case gtcp.StateLastAck, gtcp.StateClosing:
		ep := c.ep.(*gtcp.Endpoint)
		if _, send := ep.BufferUsage(); send <= 0 {
			if !c.ticket.TimeWait() {
				ep.CloseRetained()
			}
			// Cleanup can race the state read above, before the reservation.
			if closedState(ep) {
				c.ticket.EndTimeWait()
			}
		}
	}
}
