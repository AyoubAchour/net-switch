package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	ce "github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/internal/service"
)

// Remote implements Control's existing engine boundary. Only this object
// knows about the temporary adapter payload; service ownership is independent.
type Remote struct {
	mu       sync.Mutex
	connect  sync.Mutex
	rpc      *RPC
	instance string
	epoch    uint64
	snapshot ce.Snapshot
	desired  *ce.Revision
	endpoint localipc.Endpoint
	ctx      context.Context
	log      func(string)
}

func NewRemote(ctx context.Context, log func(string)) *Remote {
	return &Remote{ctx: ctx, log: log, endpoint: localipc.Endpoint{Path: localipc.DefaultPath("engine"), Kind: "engine", Service: service.Engine}, snapshot: ce.Snapshot{Status: "off"}}
}
func (r *Remote) Snapshot() ce.Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Policy contains slices/maps read by Control outside its state lock.
	b, _ := json.Marshal(r.snapshot)
	var s ce.Snapshot
	_ = json.Unmarshal(b, &s)
	return s
}
func (r *Remote) Fail(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	message := err.Error()
	r.snapshot.Status = "error"
	r.snapshot.Error = &message
}
func (r *Remote) disconnect(rpc *RPC, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rpc == rpc {
		r.rpc = nil
		r.snapshot.Status = "error"
		message := "Routing stopped, restarting: " + err.Error()
		r.snapshot.Error = &message
		rpc.Close()
		r.log(message)
	}
}
func (r *Remote) Attach(ctx context.Context, start bool) error {
	r.connect.Lock()
	defer r.connect.Unlock()
	r.mu.Lock()
	connected := r.rpc != nil
	r.mu.Unlock()
	if connected {
		return nil
	}
	c, err := localipc.Dial(ctx, r.endpoint)
	if err != nil && start {
		if err = service.Start(ctx, service.Engine); err != nil {
			return err
		}
		c, err = localipc.Dial(ctx, r.endpoint)
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
		Instance     string      `json:"engineInstanceId"`
		Snapshot     ce.Snapshot `json:"adapterSnapshot"`
		Capabilities []string    `json:"capabilities"`
	}
	if err = rpc.Call(ctx, map[string]any{"method": "hello"}, &hello); err != nil {
		return err
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
	r.rpc = rpc
	r.instance = hello.Instance
	r.epoch = attach.Epoch
	r.snapshot = hello.Snapshot
	r.snapshot.Instance = hello.Instance
	r.mu.Unlock()
	ok = true
	go r.renew(rpc)
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
			if err == nil {
				err = r.refresh(ctx)
			}
			cancel()
			if err != nil {
				r.disconnect(rpc, err)
				return
			}
		}
	}
}
func (r *Remote) call(ctx context.Context, method string, payload any, opID string, out any) error {
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
	return rpc.Call(ctx, request, out)
}
func (r *Remote) refresh(ctx context.Context) error {
	var s ce.Snapshot
	if err := r.call(ctx, "stats", adapterPayload{}, "", &s); err != nil {
		return err
	}
	r.mu.Lock()
	r.snapshot = s
	r.mu.Unlock()
	return nil
}
func (r *Remote) Start(ctx context.Context, p ce.Policy) error {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	if err := r.Attach(ctx, true); err != nil {
		r.Fail(err)
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
		r.Fail(err)
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
		if status, err := service.Query(service.Engine); err != nil || !status.Running {
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
	if err := r.call(ctx, "stop", nil, "", nil); err != nil {
		return fmt.Errorf("engine stop was not acknowledged: %w", err)
	}
	r.mu.Lock()
	r.rpc = nil
	r.snapshot = ce.Snapshot{Status: "off"}
	r.mu.Unlock()
	rpc.Close()
	return nil
}
func (r *Remote) Connections(ctx context.Context) ([]ce.Connection, error) {
	var out []ce.Connection
	err := r.call(ctx, "flows", adapterPayload{}, "", &out)
	return out, err
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
	ctx, cancel := context.WithTimeout(r.ctx, 3*time.Second)
	defer cancel()
	if err := r.call(ctx, "adapterForgetLane", adapterPayload{Line: line}, "", nil); err != nil {
		r.log("forget lane: " + err.Error())
	}
}
