package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/AyoubAchour/net-switch/internal/buildinfo"
	ce "github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/internal/service"
)

// Remote implements Control's existing engine boundary. Only this object
// knows about the temporary adapter payload; service ownership is independent.
type Remote struct {
	mu                   sync.Mutex
	connect              sync.Mutex
	rpc                  *RPC
	instance             string
	epoch                uint64
	snapshot             ce.Snapshot
	desired              *ce.Revision
	endpoint             localipc.Endpoint
	ctx                  context.Context
	log                  func(string)
	recovering, stopping bool
	recovery             uint64
	attempt              uint64
	forgotten            map[string]uint64
	forgetSequence       uint64
	dial                 func(context.Context, localipc.Endpoint) (*localipc.Conn, error)
	startService         func(context.Context, string) error
	queryService         func(string) (service.Status, error)
	waitStopped          func(context.Context, string) error
	wakeGrace            time.Time
}

func NewRemote(ctx context.Context, log func(string)) *Remote {
	return &Remote{ctx: ctx, log: log, endpoint: localipc.Endpoint{Path: localipc.DefaultPath("engine"), Kind: "engine", Service: service.Engine}, snapshot: ce.Snapshot{Status: "off"}, forgotten: map[string]uint64{}, dial: localipc.Dial, startService: service.Start, queryService: service.Query, waitStopped: service.WaitStopped}
}
func (r *Remote) Snapshot() ce.Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Policy contains slices/maps read by Control outside its state lock.
	b, _ := json.Marshal(r.snapshot)
	var s ce.Snapshot
	_ = json.Unmarshal(b, &s)
	if s.Status == "on" && r.rpc != nil {
		select {
		case <-r.rpc.Done():
			s.Status = "starting"
		default:
		}
	}
	return s
}
func (r *Remote) Fail(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failLocked(err)
}
func (r *Remote) failLocked(err error) {
	message := err.Error()
	if r.snapshot.Status != "error" || r.snapshot.FailureID == "" {
		r.snapshot.FailureID = r.instance
		if r.snapshot.FailureID == "" {
			r.snapshot.FailureID = randomID()
		}
	}
	r.snapshot.Status = "error"
	r.snapshot.Error = &message
}
func (r *Remote) disconnect(rpc *RPC, err error) {
	r.mu.Lock()
	if r.rpc != rpc || r.stopping || r.ctx.Err() != nil {
		r.mu.Unlock()
		return
	}
	r.rpc = nil
	if r.snapshot.Status != "error" {
		r.snapshot.Status = "starting"
	}
	already := r.recovering
	if !already {
		r.recovering = true
		r.recovery++
	}
	id := r.recovery
	r.mu.Unlock()
	if rpc != nil {
		rpc.Close()
	}
	r.log("engine transport interrupted; checking the existing service before counting a failure: " + err.Error())
	if !already {
		go r.recoverConnection(err, id)
	}
}
func (r *Remote) recoverConnection(cause error, id uint64) {
	defer func() {
		r.mu.Lock()
		if r.recovery == id {
			r.recovering = false
		}
		r.mu.Unlock()
	}()
	for r.ctx.Err() == nil {
		r.mu.Lock()
		stopping := r.stopping
		r.mu.Unlock()
		if stopping {
			return
		}
		ctx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
		err := r.Attach(ctx, false)
		cancel()
		if err == nil {
			r.mu.Lock()
			live := r.rpc != nil
			if live {
				select {
				case <-r.rpc.Done():
					live = false
				default:
				}
			}
			if live {
				r.recovering = false
			}
			r.mu.Unlock()
			if live {
				r.log("reattached to engine after transport interruption")
				return
			}
			continue
		}
		r.mu.Lock()
		instance, attempt := r.instance, r.attempt
		r.mu.Unlock()
		status, queryErr := r.queryService(service.Engine)
		if queryErr == nil && status.Stopped {
			r.mu.Lock()
			stopping = r.stopping
			grace := time.Now().Before(r.wakeGrace)
			current := r.recovery == id && r.rpc == nil && r.instance == instance && r.attempt == attempt
			if current && !stopping && !grace {
				r.failLocked(fmt.Errorf("engine instance exited: %w", cause))
			}
			r.mu.Unlock()
			if !current {
				continue
			}
			if grace {
				if localipc.Pause(r.ctx, time.Second) != nil {
					return
				}
				continue
			}
			return
		}
		if localipc.Pause(r.ctx, time.Second) != nil {
			return
		}
	}
}
func (r *Remote) Wake() {
	r.mu.Lock()
	r.wakeGrace = time.Now().Add(10 * time.Second)
	rpc := r.rpc
	r.mu.Unlock()
	if rpc != nil {
		go func() {
			ctx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
			defer cancel()
			if err := r.call(ctx, "renew", nil, "", nil); err != nil {
				r.disconnect(rpc, err)
			}
		}()
	}
}
func (r *Remote) Attach(ctx context.Context, start bool) error {
	r.connect.Lock()
	defer r.connect.Unlock()
	r.mu.Lock()
	connected, stopping := r.rpc != nil, r.stopping
	r.mu.Unlock()
	if connected {
		return nil
	}
	if stopping {
		return errors.New("engine stop in progress")
	}
	c, err := r.dial(ctx, r.endpoint)
	if err != nil && start {
		if err = r.startService(ctx, service.Engine); err != nil {
			return err
		}
		c, err = r.dial(ctx, r.endpoint)
	}
	if err != nil {
		return err
	}
	rpc := NewRPC(c)
	ok := false
	defer func() {
		if !ok {
			rpc.Close()
		}
	}()
	var hello struct {
		Version      string      `json:"version"`
		Instance     string      `json:"engineInstanceId"`
		Snapshot     ce.Snapshot `json:"adapterSnapshot"`
		Capabilities []string    `json:"capabilities"`
	}
	if err = rpc.Call(ctx, map[string]any{"method": "hello"}, &hello); err != nil {
		return err
	}
	if hello.Version != buildinfo.String() {
		return fmt.Errorf("engine version %q is incompatible with Control %q", hello.Version, buildinfo.String())
	}
	supported := false
	for _, v := range hello.Capabilities {
		supported = supported || v == "singbox-adapter-v1"
	}
	if !supported {
		return errors.New("engine swap is not installed: expected singbox-adapter-v1")
	}
	var attach struct {
		Epoch uint64 `json:"epoch"`
	}
	if err = rpc.Call(ctx, map[string]any{"method": "attach", "engineInstanceId": hello.Instance, "epoch": 0}, &attach); err != nil {
		return err
	}
	if attach.Epoch == 0 {
		return errors.New("engine returned a zero epoch")
	}
	r.mu.Lock()
	if r.stopping {
		r.mu.Unlock()
		return errors.New("engine stop in progress")
	}
	r.rpc = rpc
	r.instance = hello.Instance
	r.epoch = attach.Epoch
	r.snapshot = hello.Snapshot
	r.snapshot.Instance = hello.Instance
	if r.snapshot.Status == "error" {
		r.snapshot.FailureID = hello.Instance
	}
	if start && r.snapshot.Status != "on" {
		r.snapshot.Status = "starting"
		r.snapshot.Error = nil
	}
	r.mu.Unlock()
	ok = true
	go r.renew(rpc)
	go r.pollStats(rpc)
	return nil
}
func (r *Remote) renew(rpc *RPC) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.ctx.Done():
			rpc.Close()
			return
		case <-rpc.Done():
			r.disconnect(rpc, errors.New("engine connection closed"))
			return
		case <-tick.C:
			ctx, cancel := context.WithTimeout(r.ctx, 4*time.Second)
			err := r.call(ctx, "renew", nil, "", nil)
			cancel()
			if err != nil {
				r.disconnect(rpc, err)
				return
			}
		}
	}
}
func (r *Remote) pollStats(rpc *RPC) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-rpc.Done():
			return
		case <-tick.C:
			ctx, cancel := context.WithTimeout(r.ctx, 4*time.Second)
			err := r.refresh(ctx)
			cancel()
			if err != nil {
				r.log("engine stats unavailable (lease renewal remains independent): " + err.Error())
			}
		}
	}
}
func (r *Remote) call(ctx context.Context, method string, payload any, opID string, out any) error {
	return r.request(ctx, method, payload, opID, "", out)
}
func (r *Remote) request(ctx context.Context, method string, payload any, opID, cursor string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	r.mu.Lock()
	rpc, instance, epoch := r.rpc, r.instance, r.epoch
	r.mu.Unlock()
	if rpc == nil {
		return errors.New("engine service is not attached")
	}
	request := map[string]any{"method": method, "engineInstanceId": instance, "epoch": epoch}
	if payload != nil {
		request["adapter"] = payload
	}
	if opID != "" {
		request["opId"] = opID
	}
	if cursor != "" {
		request["cursor"] = cursor
	}
	return rpc.Call(ctx, request, out)
}
func (r *Remote) refresh(ctx context.Context) error {
	r.mu.Lock()
	rpc, instance := r.rpc, r.instance
	r.mu.Unlock()
	var s ce.Snapshot
	if err := r.call(ctx, "stats", adapterPayload{}, "", &s); err != nil {
		return err
	}
	r.mu.Lock()
	if r.rpc == rpc && r.instance == instance && !r.stopping {
		s.Instance = instance
		if s.Status == "error" {
			s.FailureID = instance
		}
		r.snapshot = s
		for line := range r.forgotten {
			delete(r.snapshot.Policy.Lanes, line)
		}
	}
	r.mu.Unlock()
	return nil
}
func (r *Remote) Start(ctx context.Context, p ce.Policy) error {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	r.mu.Lock()
	r.stopping = false
	r.attempt++
	// Failures before an instance exists belong to this one start attempt.
	if r.rpc == nil && !r.recovering {
		r.instance = ""
		r.snapshot.FailureID = ""
	}
	if r.snapshot.Status != "on" {
		r.snapshot.Status = "starting"
		r.snapshot.Error = nil
	}
	r.mu.Unlock()
	if err := r.Attach(ctx, true); err != nil {
		status, queryErr := r.queryService(service.Engine)
		if queryErr == nil && status.Stopped {
			r.Fail(err)
		} else {
			// SCM may still be bringing up the instance after our wait timed
			// out. Keep following it; do not leave a permanent "starting".
			r.disconnect(nil, err)
		}
		return err
	}
	r.mu.Lock()
	revision := r.desired
	r.mu.Unlock()
	if revision == nil || !reflect.DeepEqual(revision.Policy, p) {
		return errors.New("start requires a durable complete desired revision")
	}
	var ack ce.Acknowledgement
	if err := r.call(ctx, "start", adapterPayload{Revision: revision}, "", &ack); err != nil {
		// A lost response may mean the start succeeded. Reattach before
		// deciding; the next snapshot or a stopped service proves failure.
		r.mu.Lock()
		rpc := r.rpc
		r.mu.Unlock()
		if rpc != nil {
			r.disconnect(rpc, err)
		}
		return err
	}
	if ack.Number != revision.Number || ack.Hash != revision.Hash {
		return errors.New("engine start acknowledgement differs from desired policy")
	}
	return r.refresh(ctx)
}
func (r *Remote) Restore(revision *ce.Revision) { r.mu.Lock(); r.desired = revision; r.mu.Unlock() }
func (r *Remote) Apply(ctx context.Context, revision ce.Revision) (ce.Acknowledgement, error) {
	r.Restore(&revision)
	r.mu.Lock()
	rpc := r.rpc
	s := r.snapshot
	r.mu.Unlock()
	if rpc == nil || s.Status != "on" {
		// A policy may be edited while routing is off. It is not represented
		// as loaded in the remote snapshot; start will send the complete record.
		return ce.Acknowledgement{Number: revision.Number, Hash: revision.Hash, Instance: s.Instance}, nil
	}
	var ack ce.Acknowledgement
	if err := r.flushForgotten(ctx); err != nil {
		return ack, err
	}
	err := r.call(ctx, "apply", adapterPayload{Revision: &revision}, "", &ack)
	if err == nil {
		err = r.refresh(ctx)
	}
	return ack, err
}
func (r *Remote) Stop(ctx context.Context) error {
	r.mu.Lock()
	rpc := r.rpc
	r.mu.Unlock()
	if rpc == nil {
		if status, err := r.queryService(service.Engine); err != nil || status.Stopped {
			r.mu.Lock()
			r.snapshot = ce.Snapshot{Status: "off"}
			r.mu.Unlock()
			return err
		}
		if err := r.Attach(ctx, false); err != nil {
			return err
		}
		r.mu.Lock()
		rpc = r.rpc
		r.mu.Unlock()
	}
	r.mu.Lock()
	r.stopping = true
	r.mu.Unlock()
	if err := r.call(ctx, "stop", nil, "", nil); err != nil {
		r.mu.Lock()
		r.stopping = false
		r.mu.Unlock()
		return fmt.Errorf("engine stop was not acknowledged: %w", err)
	}
	// The acknowledgement precedes the engine's final journal append and
	// SCM transition. Do not start a replacement until both have completed.
	if err := r.waitStopped(ctx, service.Engine); err != nil {
		return err
	}
	r.mu.Lock()
	r.rpc = nil
	r.snapshot = ce.Snapshot{Status: "off"}
	r.instance = ""
	r.mu.Unlock()
	rpc.Close()
	return nil
}
func (r *Remote) Connections(ctx context.Context) ([]ce.Connection, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out := []ce.Connection{}
	cursor := ""
	seen := map[string]bool{}
	for {
		var page connectionPage
		if err := r.request(ctx, "flows", adapterPayload{}, "", cursor, &page); err != nil {
			return nil, err
		}
		out = append(out, page.Connections...)
		if len(out) > 65536 {
			return nil, errors.New("engine flow snapshot exceeds its entry limit")
		}
		if page.Cursor == "" {
			return out, nil
		}
		if seen[page.Cursor] || len(page.Connections) == 0 {
			return nil, errors.New("engine flow cursor made no progress")
		}
		seen[page.Cursor] = true
		cursor = page.Cursor
	}
}
func (r *Remote) CloseFlows(ctx context.Context, request ce.CloseRequest) (ce.CloseResult, error) {
	var out ce.CloseResult
	err := r.call(ctx, "closeFlows", adapterPayload{Close: &request}, request.OperationID, &out)
	return out, err
}
func (r *Remote) Probe(ctx context.Context, request ce.ProbeRequest) ce.ProbeResult {
	out := ce.ProbeResult{Outcome: ce.Unavailable}
	_ = r.call(ctx, "probe", adapterPayload{Probe: &request}, request.OperationID, &out)
	return out
}
func (r *Remote) ForgetLane(line string) {
	// Core calls this while holding its state lock. Queue the invalidation
	// locally; Apply flushes it after Core releases that lock.
	r.mu.Lock()
	defer r.mu.Unlock()
	r.forgetSequence++
	r.forgotten[line] = r.forgetSequence
	delete(r.snapshot.Policy.Lanes, line)
}
func (r *Remote) flushForgotten(ctx context.Context) error {
	r.mu.Lock()
	work := map[string]uint64{}
	for line, seq := range r.forgotten {
		work[line] = seq
	}
	r.mu.Unlock()
	for line, seq := range work {
		if err := r.call(ctx, "adapterForgetLane", adapterPayload{Line: line}, "", nil); err != nil {
			return err
		}
		r.mu.Lock()
		if r.forgotten[line] == seq {
			delete(r.forgotten, line)
		}
		r.mu.Unlock()
	}
	return nil
}
