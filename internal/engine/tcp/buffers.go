package tcp

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"gvisor.dev/gvisor/pkg/tcpip"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// Socket-option updates disable gVisor's unaccounted autotuning. A busy flow
// can grow only after the shared controller has reserved the additional bytes.
func growBuffers(ctx context.Context, ep tcpip.Endpoint, ticket flowapi.Ticket, up, down *atomic.Uint64) {
	grower, ok := ticket.(interface{ Grow(int, int) bool })
	if !ok {
		return
	}
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	var lastUp, lastDown uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		u, d := up.Load(), down.Load()
		rx, tx := ticket.Buffers()
		nextRX, nextTX := rx, tx
		if u-lastUp >= uint64(rx) {
			nextRX = min(rx*2, 8<<20)
		}
		if d-lastDown >= uint64(tx) {
			nextTX = min(tx*2, 6<<20)
		}
		lastUp, lastDown = u, d
		if (nextRX != rx || nextTX != tx) && grower.Grow(nextRX, nextTX) {
			ep.SocketOptions().SetReceiveBufferSize(int64(nextRX), true)
			ep.SocketOptions().SetSendBufferSize(int64(nextTX), true)
		}
	}
}

func waitForClose(ctx context.Context, ep tcpip.Endpoint) {
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		switch gtcp.EndpointState(ep.State()) {
		case gtcp.StateClose, gtcp.StateError, gtcp.StateTimeWait:
			return
		}
		select {
		case <-ctx.Done():
			ep.Abort()
		case <-tick.C:
		}
	}
}
