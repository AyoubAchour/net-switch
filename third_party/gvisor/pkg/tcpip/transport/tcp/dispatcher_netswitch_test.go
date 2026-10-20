package tcp

import (
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

type dispatchClock struct {
	*faketime.ManualClock
}

func (c dispatchClock) AfterFunc(d time.Duration, f func()) tcpip.Timer {
	return &dispatchTimer{Timer: c.ManualClock.AfterFunc(d, f)}
}

type dispatchTimer struct {
	tcpip.Timer
	stops int
}

func (t *dispatchTimer) Stop() bool {
	t.stops++
	return t.Timer.Stop()
}

func TestConnectedDispatchAfterTimeWait(t *testing.T) {
	clock := dispatchClock{faketime.NewManualClock()}
	s := stack.New(stack.Options{Clock: clock, TransportProtocols: []stack.TransportProtocolFactory{NewProtocol}})
	defer s.Wait()
	defer s.Close()
	ep := newEndpoint(s, protocolFromStack(s), header.IPv4ProtocolNumber, &waiter.Queue{})
	ep.snd = &sender{}
	leaves := 0
	ep.SetTimeWaitPolicy(nil, func() { leaves++ })

	// The processor selected handleConnected while the endpoint was connected.
	// Before it acquires the lock, ordered ingress completes the FIN transition.
	ep.mu.Lock()
	ep.setEndpointState(StateTimeWait)
	startTimeWait(ep)
	original := ep.timeWaitTimer.(*dispatchTimer)
	ep.mu.Unlock()
	clock.Advance(10 * time.Second)

	// Resume that exact stale dispatch without relying on goroutine scheduling.
	handleConnected(ep)
	ep.mu.Lock()
	replaced := ep.timeWaitTimer != original
	ep.mu.Unlock()
	if replaced {
		t.Error("stale connected dispatch replaced the live TIME_WAIT timer")
	}

	clock.Advance(50 * time.Second)
	if original.stops != 1 {
		t.Errorf("original timer cleanup barrier reached %d times, want 1", original.stops)
	}
	if got := ep.EndpointState(); got != StateClose {
		t.Fatalf("original TIME_WAIT deadline: state=%s, want CLOSED", got)
	}
	if leaves != 1 {
		t.Fatalf("cleanup calls=%d, want 1", leaves)
	}
}
