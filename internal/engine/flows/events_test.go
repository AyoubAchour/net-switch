package flows

import (
	"errors"
	"testing"
	"time"
)

func TestRejectionsLogWithoutBlockingForAReader(t *testing.T) {
	table := New(Defaults(), nil)
	table.now = func() time.Time { return time.Unix(100, 0) }
	done := make(chan struct{})
	go func() {
		for range 1000 {
			table.AllowReject("capped")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("logging blocked forwarding")
	}
	if got := table.Stats().EventsDropped; got != 1000-64 {
		t.Fatalf("dropped logs %d", got)
	}
	e := <-table.Events()
	if e.Type != "log" || e.App != "capped" {
		t.Fatal("missing rejection log")
	}
	for len(table.events) > 0 {
		<-table.events
	}
	table.LineError("B", errors.New("bound dial failed"))
	e = <-table.Events()
	if e.Type != "lineError" || e.Line != "B" {
		t.Fatal("missing line error")
	}
}
