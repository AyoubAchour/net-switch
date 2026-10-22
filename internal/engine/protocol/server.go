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
	"sort"
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
	leaseExpired                bool
	runtime                     Runtime
	table                       *flows.Table
	prober                      platform.Prober
	operations                  map[string]*operation
	order                       []string
	clients                     map[*connection]struct{}
	controller                  *connection
	terminal                    *terminalDelivery
	EventsDropped               atomic.Uint64
	done                        chan struct{}
	doneOnce                    sync.Once
	// TestFault is nil in production. Acceptance binaries install it explicitly.
	TestFault        func(context.Context, json.RawMessage) (any, error)
	OnCleanupFailure func(error)
}

func New(runtime Runtime, table *flows.Table, prober platform.Prober) *Server {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		panic(err)
	}
	s := &Server{Instance: hex.EncodeToString(id[:]), now: leaseNow, runtime: runtime, table: table, prober: prober, operations: map[string]*operation{}, clients: map[*connection]struct{}{}, done: make(chan struct{})}
	if counter, ok := runtime.(interface{ InitialEpoch() uint64 }); ok {
		s.epoch = counter.InitialEpoch()
	}
	return s
}
func (s *Server) Done() <-chan struct{} { return s.done }

func (s *Server) LeaseExpired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.leaseExpired
}

// Resume gives Control a bounded opportunity to run after the OS wakes.
// It cannot resurrect an instance whose cleanup already started.
func (s *Server) Resume() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.attached && !s.stopping && !s.stopped {
		grace := s.now().Add(10 * time.Second)
		if s.expires.Before(grace) {
			s.expires = grace
		}
	}
}
func (s *Server) finish() { s.doneOnce.Do(func() { close(s.done) }) }
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
	return s.handle(ctx, r, nil)
}
func (s *Server) handle(ctx context.Context, r Request, c *connection) Reply {
	result, err := s.execute(ctx, r, c)
	reply := Reply{ID: r.ID, Result: result}
	reply.stop = r.Method == "stop" && err == nil
	if err != nil {
		reply.Result = nil
		reply.Error = err.Error()
	}
	return reply
}
func (s *Server) execute(ctx context.Context, r Request, c *connection) (any, error) {
	switch r.Method {
	case "attach", "start", "apply", "stop", "closeFlows", "adapterForgetLane":
		// A new controller cannot overtake an accepted mutation. Renewals
		// remain independent of adapter file/HTTP work and disk flushes.
		s.mutation.Lock()
		defer s.mutation.Unlock()
	}
	s.mu.Lock()
	if r.Method == "terminalAck" {
		defer s.mu.Unlock()
		return s.ackTerminal(r, c)
	}
	if r.Method == "hello" {
		v := map[string]any{"version": buildinfo.String(), "engineInstanceId": s.Instance, "appliedRevision": s.table.Applied(), "epoch": s.epoch, "capabilities": []string{"tcp", "udp-nat", "revisions", "snapshots", "lease", "generation-checks", "terminal-stop"}}
		s.mu.Unlock()
		if adapter, ok := s.runtime.(AdapterRuntime); ok {
			v["capabilities"] = []string{"singbox-adapter-v1", "revisions", "lease"}
			v["adapterSnapshot"] = adapter.AdapterSnapshot()
		}
		return v, nil
	}
	if r.Method == "attach" {
		if r.Instance != s.Instance || r.Epoch != 0 || s.epoch == ^uint64(0) || s.stopping || s.stopped || (s.attached && !s.now().Before(s.expires)) {
			s.mu.Unlock()
			return nil, errors.New("attach refused")
		}
		next := s.epoch + 1
		if store, ok := s.runtime.(interface{ SaveEpoch(uint64) error }); ok {
			s.mu.Unlock()
			err := store.SaveEpoch(next)
			s.mu.Lock()
			if err != nil {
				s.mu.Unlock()
				return nil, err
			}
			if s.stopping || s.stopped || s.attached && !s.now().Before(s.expires) {
				s.mu.Unlock()
				return nil, errors.New("attach refused after lease expiry")
			}
		}
		s.epoch = next
		s.expires = s.now().Add(Lease)
		s.attached = true
		s.controller = c
		s.table.SetEpoch(s.epoch)
		epoch := s.epoch
		s.mu.Unlock()
		return map[string]any{"epoch": epoch, "leaseSeconds": 30}, nil
	}
	if s.terminal != nil {
		s.mu.Unlock()
		return nil, errors.New("engine terminal shutdown")
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
	case "testFault":
		if s.TestFault == nil {
			return nil, errors.New("test faults unavailable in production")
		}
		return s.TestFault(ctx, r.Fault)
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
		if r.All {
			return s.table.PageAll(r.Cursor)
		}
		return s.table.Page(r.Cursor)
	case "totals":
		return s.table.Totals(), nil
	case "stats":
		var data any = s.table.Stats()
		if runtime, ok := s.runtime.(interface{ Stats() any }); ok {
			data = runtime.Stats()
		}
		return map[string]any{"engine": boundStats(data), "eventsDropped": s.EventsDropped.Load()}, nil
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

// Expired fences attachment immediately, including while an accepted mutation
// is blocked in I/O. The service host can then bound whole-process cleanup.
func (s *Server) Expired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A pending adapter-lost terminal record owns shutdown.
	if s.terminal != nil || !s.attached || s.stopped || s.now().Before(s.expires) {
		return false
	}
	s.stopping = true
	s.leaseExpired = true
	return true
}

// CheckLease marks expiry before waiting for an in-flight mutation. Once
// cleanup begins, no new controller can resurrect this engine instance.
func (s *Server) CheckLease(ctx context.Context) error {
	s.mu.Lock()
	// A pending adapter-lost terminal record owns shutdown.
	if s.terminal != nil || !s.attached || s.stopped || (!s.stopping && s.now().Before(s.expires)) {
		s.mu.Unlock()
		return nil
	}
	if !s.stopping {
		s.leaseExpired = true
	}
	s.stopping = true
	s.mu.Unlock()
	s.mutation.Lock()
	defer s.mutation.Unlock()
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	err := s.runtime.Stop(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
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
				if s.OnCleanupFailure != nil {
					s.OnCleanupFailure(err)
				}
			}
		}
	}
}
// StatsBudget is what the engine's stats may take of one reply, leaving room
// under MessageLimit for the envelope.
const StatsBudget = MessageLimit - 16<<10

// boundStats keeps the stats reply deliverable whatever the diagnostics hold.
// Every production entry has its own fixed bound; hosted CI's trace sections
// (whole-system socket tables) grow with the machine. When the encoded stats
// exceed StatsBudget, the largest top-level sections are left out, largest
// first, and named with their sizes under "omittedForSize", so a reader sees
// exactly what is missing instead of losing the whole reply. Under budget the
// stats are encoded once, here, not again by the transport.
func boundStats(data any) any {
	stats, ok := data.(map[string]any)
	if !ok {
		return data
	}
	b, err := json.Marshal(stats)
	if err != nil {
		return data
	}
	if len(b) <= StatsBudget {
		return json.RawMessage(b)
	}
	sizes := make(map[string]int, len(stats))
	keys := make([]string, 0, len(stats))
	for key, value := range stats {
		encoded, _ := json.Marshal(value)
		sizes[key] = len(key) + len(encoded) + 4 // quotes, colon, comma
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return sizes[keys[i]] > sizes[keys[j]] })
	kept := make(map[string]any, len(stats))
	for key, value := range stats {
		kept[key] = value
	}
	omitted := map[string]int{}
	total := len(b)
	for _, key := range keys {
		// Room for the omission record itself.
		if total+len(omitted)*80+64 <= StatsBudget {
			break
		}
		delete(kept, key)
		omitted[key] = sizes[key]
		total -= sizes[key]
	}
	kept["omittedForSize"] = omitted
	return kept
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
