package protocol

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"
)

func TestFailedExplicitStopRepliesBeforeFatal(t *testing.T) {
	for _, read := range []bool{true, false} {
		t.Run(map[bool]string{true: "reader", false: "blocked-reader"}[read], func(t *testing.T) {
			s, base, req := setup(t)
			r := &leaseCleanupOwner{runtimeFake: base, failure: errors.New("injected stop cleanup failure")}
			s.runtime = r
			server, client := net.Pipe()
			defer client.Close()
			fatal := make(chan error, 1)
			s.OnCleanupFailure = func(err error) { fatal <- err; server.Close() }
			done := make(chan error, 1)
			go func() { done <- s.Serve(context.Background(), server) }()
			defer func() {
				client.Close()
				select {
				case <-done:
				case <-time.After(4 * time.Second):
					t.Error("transport did not join")
				}
			}()
			client.SetDeadline(time.Now().Add(5 * time.Second))
			if err := json.NewEncoder(client).Encode(req("stop")); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-fatal:
				t.Fatal("fatal preempted reply", err)
			case <-time.After(30 * time.Millisecond):
			}
			if read {
				line, err := bufio.NewReader(client).ReadBytes('\n')
				if err != nil {
					t.Fatal("stop reply lost", err)
				}
				var reply Reply
				if json.Unmarshal(line, &reply) != nil || reply.Error != r.failure.Error() {
					t.Fatal(string(line))
				}
			}
			select {
			case err := <-fatal:
				if !errors.Is(err, r.failure) || !r.owned {
					t.Fatal("wrong fatal or cleanup owner", err, r.owned)
				}
			case <-time.After(TerminalDeliveryTimeout + time.Second):
				t.Fatal("failed stop never exited")
			}
		})
	}
}
