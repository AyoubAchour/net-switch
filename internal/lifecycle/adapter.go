package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	ce "github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/internal/engine/singbox"
	"github.com/AyoubAchour/net-switch/internal/faultpoint"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
)

type adapterPayload struct {
	Revision *ce.Revision     `json:"revision,omitempty"`
	Close    *ce.CloseRequest `json:"close,omitempty"`
	Probe    *ce.ProbeRequest `json:"probe,omitempty"`
	Line     string           `json:"line,omitempty"`
}
type engineState struct {
	Instance string              `json:"engineInstanceId"`
	Epoch    uint64              `json:"epoch"`
	Applied  *ce.Acknowledgement `json:"appliedRevision"`
}

func normalizeAdapterPath(path string) string {
	if runtime.GOOS == "linux" {
		return singbox.LinuxProcessPath(path)
	}
	return path
}

type adapterRuntime struct {
	mu              sync.Mutex
	adapter         *singbox.Adapter
	data            string
	state           engineState // serialized by the protocol's lease mutex
	listConnections func(context.Context) ([]ce.Connection, error)
	pages           adapterPages
}

func (a *adapterRuntime) InitialEpoch() uint64 { return a.state.Epoch }

func (a *adapterRuntime) SaveEpoch(epoch uint64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	next := a.state
	next.Epoch = epoch
	if err := Save(filepath.Join(a.data, "engine-state.json"), next); err != nil {
		return err
	}
	a.state = next
	return nil
}
func (a *adapterRuntime) AdapterSnapshot() any {
	s := a.adapter.Snapshot()
	a.mu.Lock()
	defer a.mu.Unlock()
	s.Instance = a.state.Instance
	return s
}
func (a *adapterRuntime) Start(context.Context, policy.Revision) (policy.Applied, error) {
	return policy.Applied{}, errors.New("sing-box requires the advertised adapter payload")
}
func (a *adapterRuntime) Apply(context.Context, policy.Revision) (policy.Applied, error) {
	return policy.Applied{}, errors.New("sing-box requires the advertised adapter payload")
}
func (a *adapterRuntime) Stop(ctx context.Context) error { return a.adapter.Stop(ctx) }
func (a *adapterRuntime) AdapterRequest(ctx context.Context, r protocol.Request) (any, error) {
	var p adapterPayload
	if err := json.Unmarshal(r.Adapter, &p); err != nil {
		return nil, err
	}
	switch r.Method {
	case "start", "apply":
		if p.Revision == nil {
			return nil, errors.New("complete revision required")
		}
		encoded, err := js.Marshal(p.Revision.Policy)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(encoded)
		if p.Revision.Number == 0 || p.Revision.Hash != hex.EncodeToString(digest[:]) {
			return nil, errors.New("invalid revision number or policy hash")
		}
		before := a.adapter.Snapshot()
		if r.Method == "start" && before.Instance != "" && before.Status != "on" {
			return nil, errors.New("adapter lifetime ended; restart the engine service before starting again")
		}
		if r.Method == "apply" && a.adapter.Snapshot().Status != "on" {
			return nil, errors.New("engine has no loaded revision; start is required")
		}
		if r.Method == "start" {
			if err := a.adapter.Start(ctx, p.Revision.Policy); err != nil {
				return nil, err
			}
			s := a.adapter.Snapshot()
			if s.Status != "on" {
				if s.Error != nil {
					return nil, errors.New(*s.Error)
				}
				return nil, errors.New("adapter did not start")
			}
		}
		ack, err := a.adapter.Apply(ctx, *p.Revision)
		if err != nil {
			return nil, err
		}
		a.mu.Lock()
		ack.Instance = a.state.Instance
		next := a.state
		next.Applied = &ack
		if err := Save(filepath.Join(a.data, "engine-state.json"), next); err != nil {
			a.mu.Unlock()
			// An unrecorded applied revision cannot safely acknowledge closure
			// cutoffs. Fail open and let recovery restart a fresh instance.
			stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return nil, errors.Join(err, a.adapter.Stop(stopCtx))
		}
		a.state = next
		a.mu.Unlock()
		faultpoint.Hit(a.data, "engine-after-apply-commit")
		return ack, nil
	case "flows":
		list := a.listConnections
		if list == nil {
			list = a.adapter.Connections
		}
		return a.pages.read(ctx, r.Cursor, list)
	case "stats":
		return a.AdapterSnapshot(), nil
	case "closeFlows":
		a.mu.Lock()
		instance := a.state.Instance
		a.mu.Unlock()
		if p.Close == nil || p.Close.OperationID != r.OpID || r.OpID == "" || p.Close.Instance != instance {
			return nil, errors.New("invalid closure operation")
		}
		// The IPC instance is the service lifetime, while Clash IDs belong to
		// its guarded child. A child failure terminates this service instance.
		request := *p.Close
		request.Instance = a.adapter.Snapshot().Instance
		return a.adapter.CloseFlows(ctx, request)
	case "probe":
		if p.Probe == nil || p.Probe.OperationID != r.OpID {
			return nil, errors.New("invalid probe operation")
		}
		return a.adapter.Probe(ctx, *p.Probe), nil
	case "adapterForgetLane":
		a.adapter.ForgetLane(p.Line)
		return true, nil
	}
	return nil, fmt.Errorf("unsupported adapter method %q", r.Method)
}
