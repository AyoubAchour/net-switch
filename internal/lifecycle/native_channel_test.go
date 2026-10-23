package lifecycle

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/supervisor"
)

func TestNativeSupervisorDrainsCompletionAndFencesLateState(t *testing.T) {
	inRead, inWrite := io.Pipe()
	outRead, outWrite := io.Pipe()
	h := nativeHostMessages(&nativeProcess{pid: 77, input: inWrite, output: outRead})
	child := supervisor.NewChannel(inRead, outWrite)
	defer child.Close()
	defer h.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	id := strings.Repeat("a", 32)
	if err := child.Send(ctx, supervisor.Message{Kind: "ready", PID: 77, Instance: id}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.ready:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	first, stopFirst := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { _, err := h.status(first); done <- err }()
	var old supervisor.Message
	select {
	case old = <-child.Messages():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	stopFirst()
	if err := <-done; err == nil {
		t.Fatal("cancelled state poll succeeded")
	}
	if err := child.Send(ctx, supervisor.Message{Kind: "state", Seq: old.Seq, Instance: id, State: "off"}); err != nil {
		t.Fatal(err)
	}
	result := make(chan supervisor.Message, 1)
	go func() { m, err := h.status(ctx); result <- m; done <- err }()
	var next supervisor.Message
	select {
	case next = <-child.Messages():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := child.Send(ctx, supervisor.Message{Kind: "state", Seq: next.Seq, Instance: id, State: "on", Index: 9, Port: 42}); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-result:
		if m.State != "on" || m.Seq != next.Seq {
			t.Fatal("old state satisfied new poll", m)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := child.Flush(ctx, supervisor.Message{Kind: "complete", Instance: id, PID: 77, Code: 3}); err != nil {
		t.Fatal(err)
	}
	child.Close()
	select {
	case <-h.processed:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if m := h.complete.Load(); m == nil || m.Code != 3 {
		t.Fatal("EOF lost final outcome", m)
	}
}
