// Package protocol serves the control contract over any authenticated byte
// transport. Platform pipe/socket authentication belongs to the transport.
package protocol

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AyoubAchour/net-switch/internal/buildinfo"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
)

const Lease = 30 * time.Second

type Runtime interface {
	Start(context.Context, policy.Revision) (policy.Applied, error)
	Apply(context.Context, policy.Revision) (policy.Applied, error)
	Stop(context.Context) error
}
type AdapterRuntime interface {
	AdapterSnapshot() any
	AdapterRequest(context.Context, Request) (any, error)
}
type operation struct {
	hash   [32]byte
	result any
	err    error
	done   chan struct{}
}
type Server struct {
	mu                          sync.Mutex
	mutation                    sync.Mutex
	Instance                    string
	now                         func() time.Time
	epoch                       uint64
	expires                     time.Time
	attached, stopping, stopped bool
	runtime                     Runtime
	table                       *flows.Table
	prober                      platform.Prober
	operations                  map[string]*operation
	order                       []string
	clients                     map[*connection]struct{}
	EventsDropped               atomic.Uint64
	done                        chan struct{}
	doneOnce                    sync.Once
}

func New(runtime Runtime, table *flows.Table, prober platform.Prober) *Server {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		panic(err)
	}
	s := &Server{Instance: hex.EncodeToString(id[:]), now: time.Now, runtime: runtime, table: table, prober: prober, operations: map[string]*operation{}, clients: map[*connection]struct{}{}, done: make(chan struct{})}
	if counter, ok := runtime.(interface{ InitialEpoch() uint64 }); ok {
		s.epoch = counter.InitialEpoch()
	}
	return s
}
func (s *Server) Done() <-chan struct{} { return s.done }
func (s *Server) finish()               { s.doneOnce.Do(func() { close(s.done) }) }
func (s *Server) finishStopped() {
	s.mu.Lock()
	stopped := s.stopped
	s.mu.Unlock()
	if stopped {
		s.finish()
	}
}
func (s *Server) fence(r Request) error {
	if r.Instance != s.Instance || !s.attached || r.Epoch != s.epoch {
		return errors.New("controller fenced")
	}
	if s.stopping || !s.now().Before(s.expires) {
		return errors.New("control lease expired or engine stopping")
	}
	return nil
}

func (s *Server) Handle(ctx context.Context, r Request) Reply {
	result, err := s.execute(ctx, r)
	reply := Reply{ID: r.ID, Result: result}
	reply.stop = r.Method == "stop" && err == nil
	if err != nil {
		reply.Result = nil
		reply.Error = err.Error()
	}
	return reply
}
func (s *Server) execute(ctx context.Context, r Request) (any, error) {
	switch r.Method {
	case "attach", "start", "apply", "stop", "closeFlows", "adapterForgetLane":
		// A new controller cannot overtake an accepted mutation. Renewals
		// remain independent of adapter file/HTTP work and disk flushes.
		s.mutation.Lock()
		defer s.mutation.Unlock()
	}
	s.mu.Lock()
	if r.Method == "hello" {
		v := map[string]any{"version": buildinfo.String(), "engineInstanceId": s.Instance, "appliedRevision": s.table.Applied(), "epoch": s.epoch, "capabilities": []string{"tcp", "udp-nat", "revisions", "snapshots", "lease", "generation-checks"}}
		if adapter, ok := s.runtime.(AdapterRuntime); ok {
			v["capabilities"] = []string{"singbox-adapter-v1", "revisions", "lease"}
			v["adapterSnapshot"] = adapter.AdapterSnapshot()
		}
		s.mu.Unlock()
		return v, nil
	}
	if r.Method == "attach" {
		if r.Instance != s.Instance || r.Epoch != 0 || s.epoch == ^uint64(0) || s.stopping || s.stopped || (s.attached && !s.now().Before(s.expires)) {
			s.mu.Unlock()
			return nil, errors.New("attach refused")
		}
		next := s.epoch + 1
		if store, ok := s.runtime.(interface{ SaveEpoch(uint64) error }); ok {
			if err := store.SaveEpoch(next); err != nil {
				s.mu.Unlock()
				return nil, err
			}
		}
		s.epoch = next
		s.expires = s.now().Add(Lease)
		s.attached = true
		s.table.SetEpoch(s.epoch)
		epoch := s.epoch
		s.mu.Unlock()
		return map[string]any{"epoch": epoch, "leaseSeconds": 30}, nil
	}
	if r.Method == "stop" && s.stopped && r.Instance == s.Instance && r.Epoch == s.epoch {
		s.mu.Unlock()
		return true, nil
	}
	if r.Method == "stop" && s.stopping && r.Instance == s.Instance && r.Epoch == s.epoch {
		s.mu.Unlock()
		err := s.runtime.Stop(ctx)
		s.mu.Lock()
		if err == nil {
			s.stopped = true
		}
		s.mu.Unlock()
		return err == nil, err
	}
	if err := s.fence(r); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if r.Method == "probe" {
		s.mu.Unlock()
		return s.effect(ctx, r, func() (any, error) {
			if r.Adapter != nil {
				if adapter, ok := s.runtime.(AdapterRuntime); ok {
					return adapter.AdapterRequest(ctx, r)
				}
				return nil, errors.New("adapter payload is not supported")
			}
			if s.prober == nil {
				return nil, platform.ErrNotYet
			}
			p, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			return s.prober.Probe(p, r.Line, r.Operator)
		})
	}
	defer s.mu.Unlock()
	if r.Adapter != nil && r.Method != "stop" && r.Method != "renew" {
		if adapter, ok := s.runtime.(AdapterRuntime); ok {
			s.mu.Unlock()
			defer s.mu.Lock()
			return adapter.AdapterRequest(ctx, r)
		}
		return nil, errors.New("adapter payload is not supported")
	}
	switch r.Method {
	case "renew":
		s.expires = s.now().Add(Lease)
		return true, nil
	case "version":
		return buildinfo.String(), nil
	case "start", "apply":
		if r.Revision == nil {
			return nil, errors.New("revision required")
		}
		if r.Method == "start" {
			s.mu.Unlock()
			defer s.mu.Lock()
			return s.runtime.Start(ctx, *r.Revision)
		}
		s.mu.Unlock()
		defer s.mu.Lock()
		return s.runtime.Apply(ctx, *r.Revision)
	case "stop":
		s.stopping = true
		s.mu.Unlock()
		err := s.runtime.Stop(ctx)
		s.mu.Lock()
		if err != nil {
			return nil, err
		}
		s.stopped = true
		return true, nil
	case "flows":
		return s.table.Page(r.Cursor)
	case "totals":
		return s.table.Totals(), nil
	case "stats":
		var data any = s.table.Stats()
		if runtime, ok := s.runtime.(interface{ Stats() any }); ok {
			data = runtime.Stats()
		}
		return map[string]any{"engine": data, "eventsDropped": s.EventsDropped.Load()}, nil
	case "predict":
		return s.table.Predict(r.App)
	case "closeFlows":
		// Mutations stay under the lease lock. Unlike probes these never wait
		// on network I/O, so attach and expiry cannot race a closure.
		if r.OpID == "" {
			return nil, errors.New("opId required")
		}
		h := operationHash(r)
		key := r.Method + ":" + r.OpID
		if op := s.operations[key]; op != nil {
			if op.hash != h {
				return nil, errors.New("opId conflict")
			}
			return op.result, op.err
		}
		if err := s.makeRoom(); err != nil {
			return nil, err
		}
		result, err := s.table.CloseFlows(r.Selector, r.StartedBefore)
		done := make(chan struct{})
		close(done)
		s.operations[key] = &operation{hash: h, result: result, err: err, done: done}
		s.order = append(s.order, key)
		return result, err
	default:
		return nil, fmt.Errorf("unknown method %q", r.Method)
	}
}

func operationHash(r Request) [32]byte {
	r.ID = ""
	r.Epoch = 0
	r.Instance = ""
	b, _ := json.Marshal(r)
	return sha256.Sum256(b)
}
func (s *Server) makeRoom() error {
	if len(s.operations) < 1024 {
		return nil
	}
	for i, key := range s.order {
		select {
		case <-s.operations[key].done:
			delete(s.operations, key)
			s.order = append(s.order[:i], s.order[i+1:]...)
			return nil
		default:
		}
	}
	return errors.New("operation cache is busy")
}
func (s *Server) effect(ctx context.Context, r Request, run func() (any, error)) (any, error) {
	if r.OpID == "" {
		return nil, errors.New("opId required")
	}
	h := operationHash(r)
	key := r.Method + ":" + r.OpID
	s.mu.Lock()
	if err := s.fence(r); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if op := s.operations[key]; op != nil {
		if op.hash != h {
			s.mu.Unlock()
			return nil, errors.New("opId conflict")
		}
		s.mu.Unlock()
		select {
		case <-op.done:
			return op.result, op.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err := s.makeRoom(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	op := &operation{hash: h, done: make(chan struct{})}
	s.operations[key] = op
	s.order = append(s.order, key)
	s.mu.Unlock()
	result, err := run()
	s.mu.Lock()
	op.result = result
	op.err = err
	close(op.done)
	s.mu.Unlock()
	return result, err
}

// CheckLease shares the mutation/attach lock. Once cleanup begins, no new
// controller can resurrect this engine instance.
func (s *Server) CheckLease(ctx context.Context) error {
	s.mutation.Lock()
	defer s.mutation.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.attached || s.stopped || (!s.stopping && s.now().Before(s.expires)) {
		return nil
	}
	s.stopping = true
	err := s.runtime.Stop(ctx)
	if err == nil {
		s.stopped = true
		s.finish()
	}
	return err
}
func (s *Server) RunLease(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-s.table.Events():
			s.Emit(event)
		case <-tick.C:
			if err := s.CheckLease(ctx); err != nil {
				s.Emit(Event{Type: "fatal", Message: err.Error()})
			}
		}
	}
}
func (s *Server) Emit(event Event) {
	if len(event.Message) > 4096 {
		event.Message = event.Message[:4096]
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.clients {
		select {
		case c.events <- event:
		default:
			s.EventsDropped.Add(1)
		}
	}
}
