package protocol

import (
	"context"
	"testing"
	"time"
)

func TestForwardingEventsReachControl(t *testing.T) {
	s, runtime, _ := setup(t)
	c := &connection{events: make(chan Event, 2)}
	s.clients[c] = struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.RunLease(ctx) }()
	defer func() { cancel(); <-done }()
	runtime.table.AllowReject("capped")
	select {
	case event := <-c.events:
		if event.Type != "log" || event.App != "capped" {
			t.Fatal("wrong event")
		}
	case <-time.After(time.Second):
		t.Fatal("forwarding event was not delivered")
	}
}
