//go:build windows

package winengine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/internal/journal"
	"github.com/AyoubAchour/net-switch/internal/wintun"
)

type tailTestRuntime struct {
	table         *flows.Table
	stops         atomic.Int32
	first, second chan struct{}
	failFirst     bool
	badContext    atomic.Bool
}

func (r *tailTestRuntime) Start(_ context.Context, v policy.Revision) (policy.Applied, error) {
	return r.table.Apply(v)
}
func (r *tailTestRuntime) Apply(_ context.Context, v policy.Revision) (policy.Applied, error) {
	return r.table.Apply(v)
}
func (r *tailTestRuntime) Stop(ctx context.Context) error {
	if ctx.Err() != nil {
		r.badContext.Store(true)
		return ctx.Err()
	}
	n := r.stops.Add(1)
	if n == 1 {
		close(r.first)
	}
	if n == 2 {
		close(r.second)
	}
	if n == 1 && r.failFirst {
		return errors.New("first cleanup failed")
	}
	r.table.Unload()
	return nil
}

type tailFixture struct {
	runtime                                 *tailTestRuntime
	server                                  *protocol.Server
	loss                                    *adapterLoss
	fatal                                   chan error
	controller                              net.Conn
	enc                                     *json.Encoder
	dec                                     *json.Decoder
	epoch                                   uint64
	tail                                    shutdownTail
	pipeClosed, joined, finalized, released atomic.Bool
	finalizeErr, releaseErr, joinFatal      error
}

func newTailFixture(t *testing.T, probe ...platform.Prober) *tailFixture {
	t.Helper()
	f := &tailFixture{loss: newAdapterLoss(), fatal: make(chan error, 1)}
	f.runtime = &tailTestRuntime{table: flows.New(flows.Defaults(), nil), first: make(chan struct{}), second: make(chan struct{})}
	var prober platform.Prober
	if len(probe) != 0 {
		prober = probe[0]
	}
	f.server = protocol.New(f.runtime, f.runtime.table, prober)
	transport, controller := net.Pipe()
	f.controller, f.enc, f.dec = controller, json.NewEncoder(controller), json.NewDecoder(controller)
	controller.SetDeadline(time.Now().Add(8 * time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.server.Serve(ctx, transport) }()
	t.Cleanup(func() { cancel(); controller.Close() })
	if err := f.enc.Encode(protocol.Request{ID: "attach", Method: "attach", Instance: f.server.Instance}); err != nil {
		t.Fatal(err)
	}
	var reply protocol.Reply
	if err := f.dec.Decode(&reply); err != nil || reply.Error != "" {
		t.Fatal(reply, err)
	}
	f.epoch = uint64(reply.Result.(map[string]any)["epoch"].(float64))
	f.tail = shutdownTail{
		runtime: f.runtime, server: f.server, loss: f.loss, fatal: f.fatal, cancel: cancel,
		closePipe: func() error { f.pipeClosed.Store(true); return nil },
		join: func() {
			<-done
			f.joined.Store(true)
			if f.joinFatal != nil {
				f.fatal <- f.joinFatal
			}
		},
		finalize: sync.OnceValue(func() error {
			if f.runtime.stops.Load() == 0 {
				return errors.New("finalization preceded route cleanup")
			}
			f.finalized.Store(true)
			return f.finalizeErr
		}),
		release: func() error {
			if !f.pipeClosed.Load() || !f.joined.Load() {
				return errors.New("exclusion released before transports closed")
			}
			f.released.Store(true)
			return f.releaseErr
		},
	}
	return f
}

func (f *tailFixture) run() <-chan error {
	done := make(chan error, 1)
	go func() { done <- serveUntilStopped(context.Background(), f.tail) }()
	return done
}

func tailResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(4 * time.Second):
		t.Fatal("Serve shutdown tail did not return")
		return nil
	}
}

func TestServeTailTerminalDecisionAndLateFailures(t *testing.T) {
	for _, name := range []string{"clean", "queued fatal", "forced fatal wake", "finalizer error", "late exclusion error", "fatal during join"} {
		t.Run(name, func(t *testing.T) {
			f := newTailFixture(t)
			f.loss.handle(wintun.ErrAdapterRemoved)
			if name == "queued fatal" || name == "forced fatal wake" {
				f.fatal <- errors.New("generic failure alongside loss")
			}
			if name == "forced fatal wake" {
				<-f.loss.ready
			} // select MUST take fatal, latch still records loss
			if name == "finalizer error" {
				f.finalizeErr = errors.New("dialer close failed")
			}
			if name == "late exclusion error" {
				f.releaseErr = errors.New("ownership close failed")
			}
			if name == "fatal during join" {
				f.joinFatal = errors.New("late generic failure")
			}
			done := f.run()
			var v protocol.Terminal
			if err := f.dec.Decode(&v); err != nil {
				t.Fatal(err)
			}
			if v.Type != "stopped" || v.Reason != AdapterLostReason {
				t.Fatalf("Serve lost terminal reason: %+v", v)
			}
			earlyFailure := name == "queued fatal" || name == "forced fatal wake" || name == "finalizer error"
			if (v.CleanupError != "") != earlyFailure {
				t.Fatalf("wrong terminal failure: %+v", v)
			}
			if strings.Contains(name, "fatal") && name != "fatal during join" && !strings.Contains(v.CleanupError, "generic failure alongside loss") {
				t.Fatal(v)
			}
			if !f.finalized.Load() || f.released.Load() || f.pipeClosed.Load() {
				t.Fatal("terminal resources/exclusion finalized in wrong phase")
			}
			if err := f.enc.Encode(protocol.Request{ID: "ack", Method: "terminalAck", Instance: v.Instance, Epoch: v.Epoch, OpID: v.OpID}); err != nil {
				t.Fatal(err)
			}
			err := tailResult(t, done)
			_, clean := err.(*AdapterLostError)
			if clean != (name == "clean") {
				t.Fatalf("wrong actual Serve result: %T %v", err, err)
			}
			for _, want := range []error{f.finalizeErr, f.releaseErr, f.joinFatal} {
				if want != nil && !errors.Is(err, want) {
					t.Fatalf("Serve dropped shutdown error %v: %v", want, err)
				}
			}
			if !f.released.Load() || !f.joined.Load() || f.runtime.badContext.Load() {
				t.Fatal("Serve tail failed ordering or context contract")
			}
		})
	}
}

func TestServeTailExplicitStopWinsAndFlushesReplyBeforeClose(t *testing.T) {
	f := newTailFixture(t)
	f.loss.handle(wintun.ErrAdapterRemoved)
	if err := f.enc.Encode(protocol.Request{ID: "stop", Method: "stop", Instance: f.server.Instance, Epoch: f.epoch}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.runtime.first:
	case <-time.After(time.Second):
		t.Fatal("ordinary stop never started")
	}
	// The stop reply is blocked on net.Pipe while the actual Serve tail runs.
	done := f.run()
	select {
	case <-f.runtime.second:
	case <-time.After(time.Second):
		t.Fatal("Serve did not enter ordinary stop retry tail")
	}
	if f.pipeClosed.Load() || f.finalized.Load() || f.released.Load() {
		t.Fatal("ordinary stop finalized before reply flush")
	}
	var reply protocol.Reply
	if err := f.dec.Decode(&reply); err != nil || reply.ID != "stop" || reply.Error != "" {
		t.Fatal(reply, err)
	}
	if err := tailResult(t, done); err != nil {
		t.Fatal(err)
	}
	var terminal protocol.Terminal
	if err := f.dec.Decode(&terminal); !errors.Is(err, io.EOF) {
		t.Fatalf("stop was followed by terminal loss: %+v %v", terminal, err)
	}
}

func TestServeTailLeaseCleanupAfterFailedStopWins(t *testing.T) {
	f := newTailFixture(t)
	f.runtime.failFirst = true
	f.loss.handle(wintun.ErrAdapterRemoved)
	if err := f.enc.Encode(protocol.Request{ID: "stop", Method: "stop", Instance: f.server.Instance, Epoch: f.epoch}); err != nil {
		t.Fatal(err)
	}
	var reply protocol.Reply
	if err := f.dec.Decode(&reply); err != nil || reply.Error == "" {
		t.Fatal(reply, err)
	}
	// This is CheckLease's existing retry of an already-stopping engine; the
	// protocol package separately tests expiry before any stop request.
	if err := f.server.CheckLease(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := tailResult(t, f.run()); err != nil {
		t.Fatal(err)
	}
	var terminal protocol.Terminal
	if err := f.dec.Decode(&terminal); !errors.Is(err, io.EOF) {
		t.Fatalf("lease completion was replaced by loss: %+v %v", terminal, err)
	}
}

func TestServeTailExplicitStopUnresponsiveControllerIsBounded(t *testing.T) {
	f := newTailFixture(t)
	f.loss.handle(wintun.ErrAdapterRemoved)
	if err := f.enc.Encode(protocol.Request{ID: "stop", Method: "stop", Instance: f.server.Instance, Epoch: f.epoch}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.runtime.first:
	case <-time.After(time.Second):
		t.Fatal("ordinary stop never started")
	}
	started := time.Now()
	if err := tailResult(t, f.run()); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(started)
	if elapsed < protocol.TerminalDeliveryTimeout || elapsed > protocol.TerminalDeliveryTimeout+time.Second {
		t.Fatalf("stop reply wait was not bounded: %v", elapsed)
	}
}

func TestServeTailNoControllerStillReturnsAdapterLoss(t *testing.T) {
	r := &tailTestRuntime{table: flows.New(flows.Defaults(), nil), first: make(chan struct{}), second: make(chan struct{})}
	s := protocol.New(r, r.table, nil)
	loss := newAdapterLoss()
	loss.handle(wintun.ErrAdapterRemoved)
	err := serveUntilStopped(context.Background(), shutdownTail{
		runtime: r, server: s, loss: loss, fatal: make(chan error, 1),
		cancel: func() {}, closePipe: func() error { return nil }, join: func() {},
		finalize: func() error { return nil }, release: func() error { return nil },
	})
	if _, ok := err.(*AdapterLostError); !ok || r.stops.Load() != 1 {
		t.Fatalf("wrong no-controller Serve outcome: %v", err)
	}
	if joined := joinShutdownError(err, nil); joined != err {
		t.Fatal("successful deferred closer obscured direct exit outcome")
	}
	if joined := joinShutdownError(err, errors.New("late deferred close")); joined == err {
		t.Fatal("failed deferred closer retained clean exit outcome")
	}
}

func TestRuntimeStopAfterLossLatchRetriesCancelledCleanup(t *testing.T) {
	objects := &checkpointObjects{live: map[string]journal.Fingerprint{}}
	j := &journal.Journal{Store: &lossJournalStore{}, Lock: checkpointLock{}, Kinds: map[string]journal.Object{"test": objects}}
	session, err := j.Open(context.Background(), "boot", "instance")
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	routes := &lossTestRoutes{session: session}
	if err := routes.Capture(context.Background()); err != nil {
		t.Fatal(err)
	}
	e := engine.New(context.Background(), engine.Dependencies{Routes: routes}, flows.Defaults(), nil)
	loss := newAdapterLoss()
	e.OnTunError = loss.handle
	loss.handle(wintun.ErrAdapterRemoved)
	r := &Runtime{Engine: e, routes: &Routes{Instance: "test", timings: &phaseTimings{values: map[string]phaseTiming{}}}}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Stop(cancelled); !errors.Is(err, context.Canceled) || len(objects.live) != 1 {
		t.Fatalf("failed cleanup precondition: %v %v", err, objects.live)
	}
	if err := r.Stop(context.Background()); err != nil || len(objects.live) != 0 {
		t.Fatalf("retry kept stale failure: %v %v", err, objects.live)
	}
	// Runtime.Stop did not relinquish ownership or close the session.
	if err := session.Create(context.Background(), "test", journal.Fingerprint{"name": "still-owned"}); err != nil {
		t.Fatal(err)
	}
	if err := session.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}

type tailBlockedProbe struct{ started, closed, release chan struct{} }

func (p *tailBlockedProbe) Probe(ctx context.Context, _, _ string) (platform.ProbeResult, error) {
	close(p.started)
	<-ctx.Done()
	<-p.release
	close(p.closed)
	return platform.ProbeResult{}, ctx.Err()
}

func TestServeTailDefersFinalizationUntilTimedOutProbeActuallyJoins(t *testing.T) {
	p := &tailBlockedProbe{started: make(chan struct{}), closed: make(chan struct{}), release: make(chan struct{})}
	unblock := sync.OnceFunc(func() { close(p.release) })
	defer unblock()
	f := newTailFixture(t, p)
	f.tail.finalize = sync.OnceValue(func() error {
		select {
		case <-p.closed:
		default:
			return errors.New("dialer finalized with a live probe")
		}
		f.finalized.Store(true)
		return nil
	})
	if err := f.enc.Encode(protocol.Request{ID: "probe", Method: "probe", Instance: f.server.Instance, Epoch: f.epoch, OpID: "slow"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.started:
	case <-time.After(time.Second):
		t.Fatal("probe not running")
	}
	f.loss.handle(wintun.ErrAdapterRemoved)
	done := f.run()
	select {
	case <-f.runtime.first:
	case <-time.After(protocol.TerminalProbeJoinTimeout / 2):
		t.Fatal("Serve delayed route cleanup behind probe")
	}
	var terminal protocol.Terminal
	if err := f.dec.Decode(&terminal); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(terminal.CleanupError, "probe did not stop before finalization") || f.finalized.Load() || f.released.Load() {
		t.Fatalf("wrong timeout/finalization: %+v", terminal)
	}
	if err := f.enc.Encode(protocol.Request{ID: "ack", Method: "terminalAck", Instance: terminal.Instance, Epoch: terminal.Epoch, OpID: terminal.OpID}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Fatalf("Serve returned before probe joined: %v", err)
	default:
	}
	unblock()
	if err := tailResult(t, done); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Serve hid probe timeout: %v", err)
	}
	if !f.finalized.Load() || !f.released.Load() || f.runtime.badContext.Load() {
		t.Fatal("Serve did not finalize safely after join")
	}
}
