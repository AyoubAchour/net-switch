package protocol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

type terminalController struct {
	conn  net.Conn
	enc   *json.Encoder
	dec   *json.Decoder
	done  chan error
	epoch uint64
}

func connectTerminalController(t *testing.T, s *Server, attach bool) *terminalController {
	t.Helper()
	server, client := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	c := &terminalController{conn: client, enc: json.NewEncoder(client), dec: json.NewDecoder(client), done: make(chan error, 1)}
	go func() { c.done <- s.Serve(ctx, server) }()
	t.Cleanup(func() { cancel(); client.Close() })
	client.SetDeadline(time.Now().Add(8 * time.Second))
	if attach {
		c.call(t, Request{ID: "attach", Method: "attach", Instance: s.Instance})
		s.mu.Lock()
		c.epoch = s.epoch
		s.mu.Unlock()
	}
	return c
}

func (c *terminalController) call(t *testing.T, r Request) Reply {
	t.Helper()
	if err := c.enc.Encode(r); err != nil {
		t.Fatal(err)
	}
	var reply Reply
	if err := c.dec.Decode(&reply); err != nil {
		t.Fatal(err)
	}
	return reply
}

func (c *terminalController) terminal(t *testing.T) Terminal {
	t.Helper()
	for {
		var v Terminal
		if err := c.dec.Decode(&v); err != nil {
			t.Fatal(err)
		}
		if v.Type == "stopped" {
			return v
		}
	}
}

func newTerminalServer() (*Server, *runtimeFake) {
	f := flows.New(flows.Defaults(), nil)
	r := &runtimeFake{table: f}
	return New(r, f, nil), r
}

type terminalResult struct{ cleanup, delivery error }

func stopTerminal(s *Server) <-chan terminalResult {
	done := make(chan terminalResult, 1)
	go func() {
		cleanup, delivery := s.StopWithReason(context.Background(), "adapter lost", nil)
		done <- terminalResult{cleanup, delivery}
	}()
	return done
}

func terminalAck(s *Server, v Terminal) Request {
	return Request{ID: "terminal-ack", Method: "terminalAck", Instance: s.Instance, Epoch: v.Epoch, OpID: v.OpID}
}

func waitTerminalServe(t *testing.T, c *terminalController) {
	t.Helper()
	select {
	case <-c.done:
	case <-time.After(time.Second):
		t.Fatal("terminal transport workers did not join")
	}
}

type heldTerminalProbes struct {
	started        chan struct{}
	release        <-chan struct{}
	live, returned atomic.Int32
}

func (p *heldTerminalProbes) Probe(ctx context.Context, _, _ string) (platform.ProbeResult, error) {
	p.live.Add(1)
	p.started <- struct{}{}
	<-p.release // deliberately ignore cancellation until the test releases us
	p.live.Add(-1)
	p.returned.Add(1)
	return platform.ProbeResult{}, ctx.Err()
}

func TestTerminalBypassesFullEventsAndOutstandingReplies(t *testing.T) {
	s, runtime := newTerminalServer()
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	probes := &heldTerminalProbes{started: make(chan struct{}, Outstanding), release: release}
	s.prober = probes
	c := connectTerminalController(t, s, true)
	s.mu.Lock()
	peer := s.controller
	s.mu.Unlock()
	for i := range Outstanding {
		id := fmt.Sprintf("held-%d", i)
		if err := c.enc.Encode(Request{ID: id, Method: "probe", Instance: s.Instance, Epoch: c.epoch, OpID: id}); err != nil {
			t.Fatal(err)
		}
	}
	for range Outstanding {
		select {
		case <-probes.started:
		case <-time.After(time.Second):
			t.Fatal("all 16 probes must actually be running")
		}
	}
	assertHeld := func() {
		t.Helper()
		if live, returned := probes.live.Load(), probes.returned.Load(); live != Outstanding || returned != 0 {
			t.Fatalf("probe ownership changed before explicit release: live=%d returned=%d", live, returned)
		}
		if slots, replies := len(peer.slots), len(peer.replies); slots != Outstanding || replies != 0 {
			t.Fatalf("receipt did not use the slot-less path: held=%d queuedReplies=%d", slots, replies)
		}
	}
	assertHeld()
	for range 1000 {
		s.Emit(Event{Type: "log", Message: "busy"})
	}
	if s.EventsDropped.Load() == 0 {
		t.Fatal("queue-pressure precondition missing")
	}
	done := stopTerminal(s)
	v := c.terminal(t)
	// Probes outlive the join bound. Log and terminal writes cannot free any
	// request slot: all 16 slots still belong to blocked probe calls.
	if v.Reason != "adapter lost" || v.Instance != s.Instance || v.Epoch != c.epoch || v.OpID == "" || !strings.Contains(v.CleanupError, "probe did not stop before finalization") || runtime.stops.Load() != 1 {
		t.Fatalf("wrong terminal under held probes: %+v", v)
	}
	assertHeld()
	select {
	case <-s.Done():
		t.Fatal("finished before controller receipt acknowledgement")
	default:
	}
	if err := c.enc.Encode(terminalAck(s, v)); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	accepted := s.terminal.acked
	s.mu.Unlock()
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("valid receipt blocked behind full slots")
	}
	assertHeld() // no ACK reply was queued, and not one probe has returned
	result := <-done
	if !errors.Is(result.cleanup, context.DeadlineExceeded) || result.delivery != nil {
		t.Fatal(result)
	}
	assertHeld()
	unblock()
	waitTerminalServe(t, c)
	if probes.live.Load() != 0 || probes.returned.Load() != Outstanding {
		t.Fatal("probe workers did not all release and join")
	}
}

func TestTerminalAckFencesConnectionEpochInstanceAndNonce(t *testing.T) {
	s, _ := newTerminalServer()
	old := connectTerminalController(t, s, true)
	c := connectTerminalController(t, s, true)
	done := stopTerminal(s)
	v := c.terminal(t)
	r := terminalAck(s, v)
	// Even exact current credentials on the previous connection cannot ack.
	if old.call(t, r).Error == "" {
		t.Fatal("other connection acknowledged terminal")
	}
	for _, wrong := range []Request{
		{ID: "bad", Method: "terminalAck", Instance: s.Instance, Epoch: v.Epoch - 1, OpID: v.OpID},
		{ID: "bad", Method: "terminalAck", Instance: "other", Epoch: v.Epoch, OpID: v.OpID},
		{ID: "bad", Method: "terminalAck", Instance: s.Instance, Epoch: v.Epoch, OpID: "guessed"},
		{ID: "bad", Method: "attach", Instance: s.Instance},
		{ID: "bad", Method: "stop", Instance: s.Instance, Epoch: v.Epoch},
		{ID: "bad", Method: "renew", Instance: s.Instance, Epoch: v.Epoch},
	} {
		if c.call(t, wrong).Error == "" {
			t.Fatalf("accepted during shutdown: %+v", wrong)
		}
	}
	if err := s.CheckLease(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Done():
		t.Fatal("lease or stop bypassed pending terminal delivery")
	default:
	}
	if err := c.enc.Encode(r); err != nil {
		t.Fatal(err)
	}
	if result := <-done; result.cleanup != nil || result.delivery != nil {
		t.Fatal(result)
	}
	waitTerminalServe(t, c)
	old.conn.Close()
	waitTerminalServe(t, old)
}

func TestTerminalCleanupFailureIsReportedAndNotRetriedByLease(t *testing.T) {
	s, runtime := newTerminalServer()
	runtime.failStop = true
	c := connectTerminalController(t, s, true)
	done := stopTerminal(s)
	v := c.terminal(t)
	if v.CleanupError != "cleanup failed" {
		t.Fatalf("cleanup failure hidden: %+v", v)
	}
	if err := s.CheckLease(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runtime.stops.Load() != 1 {
		t.Fatal("lease retried terminal cleanup")
	}
	if err := c.enc.Encode(terminalAck(s, v)); err != nil {
		t.Fatal(err)
	}
	result := <-done
	if result.cleanup == nil || result.delivery != nil {
		t.Fatal(result)
	}
	waitTerminalServe(t, c)
}

func TestTerminalBoundIncludesBlockedWriteAndMissingAck(t *testing.T) {
	for _, read := range []bool{false, true} {
		t.Run(map[bool]string{false: "blocked write", true: "missing ack"}[read], func(t *testing.T) {
			s, runtime := newTerminalServer()
			c := connectTerminalController(t, s, true)
			if !read {
				s.Emit(Event{Type: "log", Message: "block writer"})
			}
			started := time.Now()
			done := stopTerminal(s)
			if read {
				c.terminal(t)
			}
			result := <-done
			elapsed := time.Since(started)
			if result.cleanup != nil || !errors.Is(result.delivery, context.DeadlineExceeded) || runtime.stops.Load() != 1 || elapsed > TerminalDeliveryTimeout+time.Second {
				t.Fatalf("unbounded or wrong terminal shutdown: %+v elapsed=%v", result, elapsed)
			}
			waitTerminalServe(t, c)
		})
	}
}

func TestTerminalWithoutControllerAndAfterDisconnect(t *testing.T) {
	for _, disconnect := range []bool{false, true} {
		s, runtime := newTerminalServer()
		if disconnect {
			c := connectTerminalController(t, s, true)
			c.conn.Close()
			waitTerminalServe(t, c)
		}
		cleanup, delivery := s.StopWithReason(context.Background(), "adapter lost", nil)
		if cleanup != nil || !errors.Is(delivery, ErrNoController) || runtime.stops.Load() != 1 {
			t.Fatal(cleanup, delivery)
		}
	}
}

func TestDisconnectWhileTerminalPending(t *testing.T) {
	s, runtime := newTerminalServer()
	c := connectTerminalController(t, s, true)
	done := stopTerminal(s)
	c.terminal(t)
	c.conn.Close()
	result := <-done
	if result.cleanup != nil || !errors.Is(result.delivery, io.ErrClosedPipe) || runtime.stops.Load() != 1 {
		t.Fatal(result)
	}
	waitTerminalServe(t, c)
}

func TestTerminalReceiptImmediatelyFollowedByEOF(t *testing.T) {
	s, _ := newTerminalServer()
	c := connectTerminalController(t, s, true)
	done := stopTerminal(s)
	v := c.terminal(t)
	if err := c.enc.Encode(terminalAck(s, v)); err != nil {
		t.Fatal(err)
	}
	c.conn.Close()
	if result := <-done; result.cleanup != nil || result.delivery != nil {
		t.Fatal("received terminal treated as disconnected before receipt", result)
	}
	waitTerminalServe(t, c)
}

func TestExplicitStopWinsBeforeTerminal(t *testing.T) {
	s, runtime, req := setup(t)
	call(t, s, req("stop"))
	cleanup, delivery := s.StopWithReason(context.Background(), "adapter lost", nil)
	if cleanup != nil || !errors.Is(delivery, ErrShutdownInProgress) || runtime.stops.Load() != 1 || s.terminal != nil {
		t.Fatal("adapter loss overrode explicit stop", cleanup, delivery)
	}
}

type terminalProbe struct {
	started chan struct{}
	closed  chan struct{}
	release <-chan struct{}
}

func (p *terminalProbe) Probe(ctx context.Context, _, _ string) (platform.ProbeResult, error) {
	close(p.started)
	<-ctx.Done()
	if p.release != nil {
		<-p.release
	}
	close(p.closed) // represents the probe's native socket close before return
	return platform.ProbeResult{}, ctx.Err()
}

type terminalCleanupRuntime struct {
	*runtimeFake
	stopped chan error
	delay   time.Duration
}

func (r *terminalCleanupRuntime) Stop(ctx context.Context) error {
	r.stopped <- ctx.Err()
	time.Sleep(r.delay)
	return r.runtimeFake.Stop(ctx)
}

func TestTerminalCancelsAndJoinsProbeBeforeFinalization(t *testing.T) {
	s, runtime := newTerminalServer()
	p := &terminalProbe{started: make(chan struct{}), closed: make(chan struct{})}
	s.prober = p
	c := connectTerminalController(t, s, true)
	if err := c.enc.Encode(Request{ID: "probe", Method: "probe", Instance: s.Instance, Epoch: c.epoch, OpID: "pending-probe"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.started:
	case <-time.After(time.Second):
		t.Fatal("probe precondition missing")
	}
	done := make(chan terminalResult, 1)
	go func() {
		cleanup, delivery := s.StopWithReason(context.Background(), "adapter lost", func() error {
			select {
			case <-p.closed:
				return nil
			default:
				return errors.New("probe still owns socket at finalization")
			}
		})
		done <- terminalResult{cleanup, delivery}
	}()
	v := c.terminal(t)
	if v.CleanupError != "" || runtime.stops.Load() != 1 {
		t.Fatalf("terminal cleanup preceded probe close: %+v", v)
	}
	if err := c.enc.Encode(terminalAck(s, v)); err != nil {
		t.Fatal(err)
	}
	if result := <-done; result.cleanup != nil || result.delivery != nil {
		t.Fatal(result)
	}
	waitTerminalServe(t, c)
}

func TestStubbornProbeDoesNotDelayRoutingCleanupOrSpendItsContext(t *testing.T) {
	s, runtime := newTerminalServer()
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	p := &terminalProbe{started: make(chan struct{}), closed: make(chan struct{}), release: release}
	s.prober = p
	stopped := make(chan error, 1)
	s.runtime = &terminalCleanupRuntime{runtimeFake: runtime, stopped: stopped}
	c := connectTerminalController(t, s, true)
	if err := c.enc.Encode(Request{ID: "probe", Method: "probe", Instance: s.Instance, Epoch: c.epoch, OpID: "stubborn"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.started:
	case <-time.After(time.Second):
		t.Fatal("probe never started")
	}
	var finalized atomic.Bool
	done := make(chan terminalResult, 1)
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	go func() {
		cleanup, delivery := s.StopWithReason(cleanupCtx, "adapter lost", func() error { finalized.Store(true); return nil })
		done <- terminalResult{cleanup, delivery}
	}()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("routing cleanup received exhausted context: %v", err)
		}
	case <-time.After(TerminalProbeJoinTimeout / 2):
		t.Fatal("routing cleanup waited behind probe join")
	}
	v := c.terminal(t)
	if !strings.Contains(v.CleanupError, "probe did not stop before finalization") || finalized.Load() {
		t.Fatalf("unsafe or hidden probe timeout: %+v", v)
	}
	if err := c.enc.Encode(terminalAck(s, v)); err != nil {
		t.Fatal(err)
	}
	result := <-done
	if !errors.Is(result.cleanup, context.DeadlineExceeded) || result.delivery != nil {
		t.Fatal(result)
	}
	unblock()
	waitTerminalServe(t, c)
}

func TestTerminalDeliveryDeadlineStartsAfterDelayedCleanup(t *testing.T) {
	s, runtime := newTerminalServer()
	const delay = 1500 * time.Millisecond
	s.runtime = &terminalCleanupRuntime{runtimeFake: runtime, stopped: make(chan error, 1), delay: delay}
	c := connectTerminalController(t, s, true)
	started := time.Now()
	done := stopTerminal(s)
	c.terminal(t) // deliberately do not acknowledge
	result := <-done
	elapsed := time.Since(started)
	if result.cleanup != nil || !errors.Is(result.delivery, context.DeadlineExceeded) || elapsed < delay+TerminalDeliveryTimeout || elapsed > delay+TerminalDeliveryTimeout+time.Second {
		t.Fatalf("deadline borrowed cleanup time: %+v elapsed=%v", result, elapsed)
	}
	waitTerminalServe(t, c)
}

func TestLeaseCleanupWinsWithoutCallingTerminalFinalizer(t *testing.T) {
	s, runtime, _ := setup(t)
	s.mu.Lock()
	expired := s.expires.Add(time.Nanosecond)
	s.now = func() time.Time { return expired }
	s.mu.Unlock()
	if err := s.CheckLease(context.Background()); err != nil {
		t.Fatal(err)
	}
	called := false
	cleanup, delivery := s.StopWithReason(context.Background(), "adapter lost", func() error { called = true; return nil })
	if cleanup != nil || !errors.Is(delivery, ErrShutdownInProgress) || called || runtime.stops.Load() != 1 {
		t.Fatal(cleanup, delivery, called)
	}
	select {
	case <-s.Done():
	default:
		t.Fatal("lease did not own completion")
	}
}
