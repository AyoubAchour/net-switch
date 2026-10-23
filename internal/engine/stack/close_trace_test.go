package stack_test

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"gvisor.dev/gvisor/pkg/tcpip"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// closeTrace records one test's admission decisions so a failure can show which
// ticket held the retained slot, which ticket each endpoint's TIME_WAIT policy
// was installed with, and what releaseAdmission read.
//
// It is opt-in: peer.trace is nil in every other test, so peerControl allocates
// nothing extra and the forwarder's observer probes find no sink. The record is
// a per-test slice, printed only when the test fails.
type closeTrace struct {
	mu      sync.Mutex
	seq     int
	tickets []*traceTicket
	events  []string
}

type traceTicket struct {
	trace    *closeTrace
	seq      int
	port     uint16
	inner    flowapi.Ticket
	reserved bool // a TimeWait/Closing call returned true and nothing released it
	overflow bool // the first retain call on this ticket was refused
	timeWait int
	closing  int
	ended    int
	retired  bool
	closed   bool
}

func (t *closeTrace) wrap(inner flowapi.Ticket, tuple platform.Tuple) flowapi.Ticket {
	t.mu.Lock()
	defer t.mu.Unlock()
	tk := &traceTicket{trace: t, seq: len(t.tickets) + 1, port: tuple.Source.Port(), inner: inner}
	t.tickets = append(t.tickets, tk)
	t.record("ticket %d created for port %d (%p)", tk.seq, tk.port, tk)
	return tk
}

// TimeWaitPolicy is called by the forwarder after it binds the endpoint's
// TIME_WAIT enter callback to a ticket.
func (t *closeTrace) TimeWaitPolicy(id gv.TransportEndpointID, ep tcpip.Endpoint, ticket flowapi.Ticket) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.record("TIME_WAIT policy installed on endpoint %p (port %d) with ticket %s", ep, id.RemotePort, t.name(ticket))
}

// Release is called by the forwarder with the state releaseAdmission read.
func (t *closeTrace) Release(id gv.TransportEndpointID, state tcp.EndpointState, ticket flowapi.Ticket) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.record("releaseAdmission port %d read state %s with ticket %s", id.RemotePort, state, t.name(ticket))
}

func (t *closeTrace) name(v flowapi.Ticket) string {
	if tk, ok := v.(*traceTicket); ok {
		return fmt.Sprintf("%d (%p)", tk.seq, tk)
	}
	return fmt.Sprintf("untraced (%p)", v)
}

func (t *closeTrace) record(format string, args ...any) {
	t.seq++
	t.events = append(t.events, fmt.Sprintf("%3d  %s", t.seq, fmt.Sprintf(format, args...)))
}

// The rest of flowapi.Ticket passes straight through, so a traced connection
// resolves, accounts and cancels exactly like an untraced one.
func (t *traceTicket) Resolve(owner platform.Owner) (flowapi.Decision, error) {
	return t.inner.Resolve(owner)
}

func (t *traceTicket) Buffers() (receive, send int) { return t.inner.Buffers() }

func (t *traceTicket) Established(addr netip.Addr) { t.inner.Established(addr) }

func (t *traceTicket) Add(up, down uint64) { t.inner.Add(up, down) }

func (t *traceTicket) SetCancel(cancel context.CancelFunc) { t.inner.SetCancel(cancel) }

func (t *traceTicket) TimeWait() bool {
	ok := t.inner.TimeWait()
	t.trace.call(t, "TimeWait", ok)
	return ok
}

func (t *traceTicket) Closing() bool {
	ok := t.inner.Closing()
	t.trace.call(t, "Closing", ok)
	return ok
}

func (t *traceTicket) EndTimeWait() {
	t.inner.EndTimeWait()
	t.trace.note(t, "EndTimeWait")
}

func (t *traceTicket) Retire() {
	t.inner.Retire()
	t.trace.note(t, "Retire")
}

func (t *traceTicket) Close() {
	t.inner.Close()
	t.trace.note(t, "Close")
}

// Grow and Shrink keep the maintenance sweep's ticket assertion satisfied, so a
// traced connection resizes its buffers exactly like an untraced one.
func (t *traceTicket) Grow(receive, send int) bool {
	if g, ok := t.inner.(interface{ Grow(int, int) bool }); ok {
		return g.Grow(receive, send)
	}
	return false
}

func (t *traceTicket) Shrink(receive, send int) {
	if s, ok := t.inner.(interface{ Shrink(int, int) }); ok {
		s.Shrink(receive, send)
	}
}

func (t *closeTrace) call(tk *traceTicket, name string, result bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch name {
	case "TimeWait":
		tk.timeWait++
		if result {
			tk.reserved = true
		}
	case "Closing":
		tk.closing++
		if result {
			tk.reserved = true
		} else if tk.closing == 1 && tk.timeWait == 0 {
			tk.overflow = true
		}
	}
	t.record("ticket %d (%p) %s -> %t", tk.seq, tk, name, result)
}

func (t *closeTrace) note(tk *traceTicket, name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch name {
	case "EndTimeWait":
		tk.ended++
		tk.reserved = false
	case "Retire":
		tk.retired = true
	case "Close":
		tk.closed = true
		tk.reserved = false
	}
	t.record("ticket %d (%p) %s", tk.seq, tk, name)
}

// dump renders the whole record. TimeWait is the endpoint's TIME_WAIT enter
// callback: setEndpointState(StateTimeWait) runs it and startTimeWait closes the
// endpoint when it returns false, so its result is that transition's decision.
func (t *closeTrace) dump(g flows.Gauges, first, second *tcp.Endpoint) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "admission trace (%d tickets)\n", len(t.tickets))
	fmt.Fprintf(&b, "  gauges: TimeWait=%d TimeWaitSkipped=%d ClosingOverflow=%d ClosingOverflowPeak=%d Flows=%d\n",
		g.TimeWait, g.TimeWaitSkipped, g.ClosingOverflow, g.ClosingOverflowPeak, g.Flows)
	fmt.Fprintf(&b, "  endpoints: first=%p %s second=%p %s\n", first, tcp.EndpointState(first.State()), second, tcp.EndpointState(second.State()))
	fmt.Fprintf(&b, "  (a ticket's TimeWait is the endpoint's TIME_WAIT enter callback: setEndpointState(StateTimeWait)\n")
	fmt.Fprintf(&b, "   runs it, then startTimeWait closes the endpoint when it returns false.)\n")
	for _, line := range t.events {
		fmt.Fprintf(&b, "  %s\n", line)
	}
	for _, tk := range t.tickets {
		holder := ""
		if tk.reserved {
			holder = "  <- retained slot holder"
		}
		fmt.Fprintf(&b, "  ticket %d port %d (%p): reserved=%t overflow=%t timeWait=%d closing=%d ended=%d retired=%t closed=%t%s\n",
			tk.seq, tk.port, tk, tk.reserved, tk.overflow, tk.timeWait, tk.closing, tk.ended, tk.retired, tk.closed, holder)
	}
	return b.String()
}
