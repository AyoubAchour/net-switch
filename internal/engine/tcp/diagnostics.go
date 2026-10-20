package tcp

import (
	"sort"

	"gvisor.dev/gvisor/pkg/tcpip"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// Diagnostic describes the app-facing TCP leg. The native leg has a separate
// sequence space; NativeLocal links it to the operating system's socket stats.
// These are observations of existing counters, not additional per-flow state.
type Diagnostic struct {
	Source, Destination, NativeLocal                      string
	State                                                 string
	RelayClosed                                           bool
	Up, Down                                              uint64
	ReceiveBytes, SendBytes                               int
	ReceiveGrant, SendGrant                               int
	RTT, RTO                                              int64 // nanoseconds
	CongestionState, CongestionWindow                     uint32
	SegmentsReceived, SegmentsSent                        uint64
	Retransmits, FastRetransmits, RTOs                    uint64
	ReceiveBufferDrops, SegmentQueueDrops, ChecksumErrors uint64
	MalformedPackets, ClosedReceiver, ZeroReceiveWindow   uint64
	SendFailures, NoRoute, ReadErrors                     uint64
	// gVisor's WriteClosed counter includes ErrWouldBlock: these rejected
	// attempts are normal backpressure too, not evidence of dropped bytes.
	WriteAttemptsRejected, WriteInvalidState, WriteInvalidArgs uint64
}

// Diagnostics takes a bounded snapshot without holding the admission lock
// while inspecting endpoints. Above limit it reports the omitted count instead
// of walking/allocating for all 65,536 idle connections on every stats request.
func (f *Forwarder) Diagnostics(limit int) ([]Diagnostic, int) {
	f.mu.RLock()
	n := len(f.connections) + len(f.retired)
	if limit <= 0 || n > limit {
		f.mu.RUnlock()
		return nil, n
	}
	connections := make([]*connection, 0, n)
	for _, c := range f.connections {
		connections = append(connections, c)
	}
	for c := range f.retired {
		connections = append(connections, c)
	}
	f.mu.RUnlock()
	result := make([]Diagnostic, 0, n)
	for _, c := range connections {
		s, ok := c.ep.Stats().(*gtcp.Stats)
		if !ok {
			continue
		}
		t := tuple(c.id)
		d := Diagnostic{
			Source: t.Source.String(), Destination: t.Destination.String(),
			State: gtcp.EndpointState(c.ep.State()).String(), Up: c.up.Load(), Down: c.down.Load(),
			SegmentsReceived: s.SegmentsReceived.Value(), SegmentsSent: s.SegmentsSent.Value(),
			Retransmits: s.SendErrors.Retransmits.Value(), FastRetransmits: s.SendErrors.FastRetransmit.Value(), RTOs: s.SendErrors.Timeouts.Value(),
			ReceiveBufferDrops: s.ReceiveErrors.ReceiveBufferOverflow.Value(), SegmentQueueDrops: s.ReceiveErrors.SegmentQueueDropped.Value(),
			ChecksumErrors: s.ReceiveErrors.ChecksumErrors.Value(), MalformedPackets: s.ReceiveErrors.MalformedPacketsReceived.Value(),
			ClosedReceiver: s.ReceiveErrors.ClosedReceiver.Value(), ZeroReceiveWindow: s.ReceiveErrors.ZeroRcvWindowState.Value(),
			SendFailures:          s.SendErrors.SendToNetworkFailed.Value() + s.SendErrors.SegmentSendToNetworkFailed.Value() + s.SendErrors.SynSendToNetworkFailed.Value(),
			NoRoute:               s.SendErrors.NoRoute.Value(),
			ReadErrors:            s.ReadErrors.ReadClosed.Value() + s.ReadErrors.InvalidEndpointState.Value() + s.ReadErrors.NotConnected.Value(),
			WriteAttemptsRejected: s.WriteErrors.WriteClosed.Value(),
			WriteInvalidState:     s.WriteErrors.InvalidEndpointState.Value(), WriteInvalidArgs: s.WriteErrors.InvalidArgs.Value(),
		}
		d.ReceiveGrant, d.SendGrant = c.ticket.Buffers()
		if ep, ok := c.ep.(interface{ BufferUsage() (int, int) }); ok {
			d.ReceiveBytes, d.SendBytes = ep.BufferUsage()
		}
		var info tcpip.TCPInfoOption
		if err := c.ep.GetSockOpt(&info); err == nil {
			d.RTT, d.RTO = int64(info.RTT), int64(info.RTO)
			d.CongestionState, d.CongestionWindow = uint32(info.CcState), info.SndCwnd
		}
		if relay := c.ready.Load(); relay != nil {
			d.NativeLocal = relay.remote.LocalAddr().String()
			d.RelayClosed = relay.closed.Load()
		}
		result = append(result, d)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Source != result[j].Source {
			return result[i].Source < result[j].Source
		}
		return result[i].Destination < result[j].Destination
	})
	return result, n - len(result)
}
