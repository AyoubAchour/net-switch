package protocol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
)

type runtimeFake struct {
	table *flows.Table
	stops atomic.Int64
	failStop bool
}

func (r *runtimeFake) Start(_ context.Context, v policy.Revision) (policy.Applied, error) {
	return r.table.Apply(v)
}
func (r *runtimeFake) Apply(_ context.Context, v policy.Revision) (policy.Applied, error) {
	return r.table.Apply(v)
}
func (r *runtimeFake) Stop(context.Context) error {
	r.stops.Add(1)
	if r.failStop { r.failStop = false; return errors.New("cleanup failed") }
	r.table.Unload()
	r.table.CloseAll()
	return nil
}

func TestFailedStopCanRetry(t *testing.T) {
	s, runtime, req := setup(t)
	runtime.failStop = true
	if s.Handle(context.Background(), req("stop")).Error == "" { t.Fatal("cleanup failure acknowledged") }
	call(t, s, req("stop"))
}
func revision(n uint64) policy.Revision {
	c := policy.Config{Lines: []platform.Line{{ID: "A"}}}
	return policy.Revision{N: n, Hash: policy.Hash(c), Config: c}
}
func setup(t *testing.T) (*Server, *runtimeFake, func(string) Request) {
	f := flows.New(flows.Defaults(), nil)
	runtime := &runtimeFake{table: f}
	s := New(runtime, f, nil)
	req := func(method string) Request {
		return Request{ID: method, Method: method, Instance: s.Instance, Epoch: 1}
	}
	if r := s.Handle(context.Background(), req("attach")); r.Error != "" {
		t.Fatal(r)
	}
	return s, runtime, req
}
func call(t *testing.T, s *Server, r Request) Reply {
	t.Helper()
	out := s.Handle(context.Background(), r)
	if out.Error != "" {
		t.Fatal(out.Error)
	}
	return out
}

func TestRevisionProtocol(t *testing.T) {
	s, _, req := setup(t)
	r := req("start")
	v := revision(2)
	r.Revision = &v
	a := call(t, s, r).Result.(policy.Applied)
	if call(t, s, r).Result != a {
		t.Fatal("same revision changed")
	}
	v.Config.IPv6 = true
	v.Hash = policy.Hash(v.Config)
	if s.Handle(context.Background(), r).Error == "" {
		t.Fatal("conflict accepted")
	}
	v = revision(1)
	if s.Handle(context.Background(), r).Error == "" {
		t.Fatal("stale accepted")
	}
}
func TestLeaseFencingAndLapse(t *testing.T) {
	s, runtime, req := setup(t)
	r := req("attach")
	r.Epoch = 2
	call(t, s, r)
	if s.Handle(context.Background(), req("renew")).Error == "" {
		t.Fatal("old controller renewed")
	}
	s.mu.Lock()
	expired := s.expires.Add(time.Nanosecond)
	s.now = func() time.Time { return expired }
	s.mu.Unlock()
	if err := s.CheckLease(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.Epoch = 3
	if s.Handle(context.Background(), r).Error == "" {
		t.Fatal("attach resurrected cleanup")
	}
	if runtime.stops.Load() != 1 {
		t.Fatal("lease did not clean up once")
	}
	s.CheckLease(context.Background())
	if runtime.stops.Load() != 1 {
		t.Fatal("cleanup repeated")
	}
}
func TestStopIsIdempotent(t *testing.T) {
	s, runtime, req := setup(t)
	call(t, s, req("stop"))
	call(t, s, req("stop"))
	if runtime.stops.Load() != 1 {
		t.Fatal("stop repeated")
	}
}
func TestCloseOperationCutoffAndIdempotency(t *testing.T) {
	s, _, req := setup(t)
	v := revision(1)
	r := req("start")
	r.Revision = &v
	call(t, s, r)
	tuple := platform.Tuple{Source: netip.MustParseAddrPort("198.18.0.2:40000"), Destination: netip.MustParseAddrPort("203.0.113.2:443")}
	old, _ := s.table.Begin("tcp", tuple)
	old.Resolve(platform.Owner{AppID: "app"})
	old.SetCancel(old.Close)
	v = revision(2)
	r.Method = "apply"
	a := call(t, s, r).Result.(policy.Applied)
	fresh, _ := s.table.Begin("tcp", tuple)
	fresh.Resolve(platform.Owner{AppID: "app"})
	defer fresh.Close()
	fresh.SetCancel(fresh.Close)
	r = req("closeFlows")
	r.OpID = "closure"
	r.Selector = flows.Selector{Line: "A"}
	r.StartedBefore = a.Point
	first := call(t, s, r).Result
	if call(t, s, r).Result != first || s.table.Stats().Flows != 1 {
		t.Fatal("closure retry closed newer flow")
	}
	r.StartedBefore = 0
	if s.Handle(context.Background(), r).Error == "" {
		t.Fatal("opId conflict accepted")
	}
	r.OpID = "empty"
	r.Selector = flows.Selector{}
	if s.Handle(context.Background(), r).Error == "" {
		t.Fatal("empty selector accepted")
	}
}

type probeFake struct {
	calls atomic.Int64
	gate  chan struct{}
}

func (p *probeFake) Probe(ctx context.Context, _, _ string) (platform.ProbeResult, error) {
	p.calls.Add(1)
	select {
	case <-p.gate:
		return platform.ProbeResult{OK: true}, nil
	case <-ctx.Done():
		return platform.ProbeResult{}, ctx.Err()
	}
}
func TestConcurrentProbeIdempotencyDoesNotBlockRenew(t *testing.T) {
	s, _, req := setup(t)
	p := &probeFake{gate: make(chan struct{})}
	s.prober = p
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			r := req("probe")
			r.OpID = "probe1"
			if out := s.Handle(context.Background(), r); out.Error != "" {
				t.Error(out.Error)
			}
		})
	}
	deadline := time.Now().Add(time.Second)
	for p.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	call(t, s, req("renew"))
	close(p.gate)
	wg.Wait()
	if p.calls.Load() != 1 {
		t.Fatal("probe executed twice")
	}
}
func TestOperationCacheBound(t *testing.T) {
	s, _, req := setup(t)
	for i := range 1100 {
		r := req("closeFlows")
		r.OpID = fmt.Sprint(i)
		r.Selector = flows.Selector{Line: "A"}
		call(t, s, r)
	}
	if len(s.operations) != 1024 {
		t.Fatal("unbounded op cache")
	}
}
func TestDecodeLimitsAndUnknownFields(t *testing.T) {
	for _, raw := range []string{`{"id":"1","method":"hello","surprise":1}`, `{"id":"1","method":"apply","revision":{"n":1,"hash":"x","config":{"lines":[],"bad":1}}}`, `{"id":"1"} {}`, string(make([]byte, MessageLimit+1))} {
		if _, err := Decode([]byte(raw)); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
	if _, err := Decode([]byte(`{"id":"1","method":"hello"}`)); err != nil {
		t.Fatal(err)
	}
}
func TestSlowReaderDoesNotBlockForwardingOrLease(t *testing.T) {
	s, _, req := setup(t)
	server, client := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer client.Close()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, server) }()
	writes := make(chan error, 1)
	go func() {
		for i := range 16 {
			r := req("hello")
			r.ID = fmt.Sprint(i)
			b, _ := json.Marshal(r)
			if _, err := client.Write(append(b, '\n')); err != nil {
				writes <- err
				return
			}
		}
		writes <- nil
	}()
	select {
	case err := <-writes:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("request slots stalled early")
	}
	for range 1000 {
		s.Emit(Event{Type: "log", Message: "busy"})
	}
	if s.EventsDropped.Load() == 0 {
		t.Fatal("unbounded events")
	}
	call(t, s, req("renew"))
	s.mu.Lock()
	for c := range s.clients {
		if len(c.slots) > 16 {
			t.Error("too many outstanding requests")
		}
	}
	s.mu.Unlock()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("slow reader prevented shutdown")
	}
}

type captureWriter struct {
	values []json.RawMessage
	cancel context.CancelFunc
}

func (w *captureWriter) Write(b []byte) (int, error) {
	w.values = append(w.values, append([]byte(nil), b...))
	if len(w.values) == 2 {
		w.cancel()
	}
	return len(b), nil
}
func TestReplyPriority(t *testing.T) {
	c := &connection{events: make(chan Event, 2), replies: make(chan Reply, 2), slots: make(chan struct{}, 2)}
	c.events <- Event{Type: "log", Message: "old"}
	c.slots <- struct{}{}
	c.replies <- Reply{ID: "control", Result: true}
	ctx, cancel := context.WithCancel(context.Background())
	w := &captureWriter{cancel: cancel}
	err := c.write(ctx, w)
	if !errors.Is(err, context.Canceled) || len(w.values) != 2 {
		t.Fatal(err)
	}
	var first Reply
	if json.Unmarshal(w.values[0], &first) != nil || first.ID != "control" {
		t.Fatal("log beat control reply")
	}
}
