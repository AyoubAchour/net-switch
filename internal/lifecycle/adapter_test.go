package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apps"
	ce "github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/internal/engine/singbox"
	"github.com/AyoubAchour/net-switch/internal/lines"
)

type memoryAdapterRuntime struct{ *adapterRuntime }

func (*memoryAdapterRuntime) SaveEpoch(uint64) error { return nil }
func TestInvalidStartNeverReachesAdapterLifecycle(t *testing.T) {
	verified := false
	adapter := singbox.New(singbox.Options{DataDir: t.TempDir(), Verify: func() error { verified = true; return errors.New("invalid revision must not get here") }})
	runtime := &adapterRuntime{adapter: adapter}
	payload, _ := json.Marshal(adapterPayload{Revision: &ce.Revision{Number: 1, Hash: "wrong", Policy: ce.Policy{Lines: []lines.Line{{ID: "a1", Alias: "Ethernet"}}, AppLines: apps.Pins{}, Shares: lines.Shares{}, Lanes: map[string]string{"a1": "a1"}, Blocked: []string{}}}})
	var validShape adapterPayload
	if err := json.Unmarshal(payload, &validShape); err != nil {
		t.Fatal("test did not reach hash validation", err)
	}
	if _, err := runtime.AdapterRequest(context.Background(), protocol.Request{Method: "start", Adapter: payload}); err == nil {
		t.Fatal("invalid start accepted")
	}
	if verified || adapter.Snapshot().Status != "off" {
		t.Fatal("invalid revision changed the adapter lifecycle")
	}
}
func TestServiceFlowSnapshotLargerThanOneFrame(t *testing.T) {
	connections := make([]ce.Connection, 10000)
	for i := range connections {
		connections[i].ID = strconv.Itoa(i)
		connections[i].Metadata.ProcessPath = strings.Repeat("application-folder/", 14) + strconv.Itoa(i)
		connections[i].Chains = []string{"line-a1"}
	}
	encoded, err := json.Marshal(connections)
	if err != nil || len(encoded) <= protocol.MessageLimit {
		t.Fatal("test did not exceed a frame", err, len(encoded))
	}
	runtime := &adapterRuntime{listConnections: func(context.Context) ([]ce.Connection, error) { return connections, nil }}
	table := flows.New(flows.Defaults(), nil)
	server := protocol.New(&memoryAdapterRuntime{runtime}, table, nil)
	// This is an in-memory byte transport, with no service, adapter or socket.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	attach := server.Handle(ctx, protocol.Request{ID: "attach", Method: "attach", Instance: server.Instance})
	if attach.Error != "" {
		t.Fatal(attach.Error)
	}
	left, right := net.Pipe()
	go server.Serve(ctx, left)
	rpc := NewRPC(right)
	defer rpc.Close()
	remote := &Remote{rpc: rpc, instance: server.Instance, epoch: 1, ctx: ctx}
	got, err := remote.Connections(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(connections) || got[len(got)-1].ID != connections[len(connections)-1].ID {
		t.Fatal("flow snapshot lost records")
	}
}
