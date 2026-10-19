package protocol

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
)

func FuzzProtocol(f *testing.F) {
	for _, method := range []string{"hello", "renew", "flows", "totals", "stats", "predict", "closeFlows", "stop", "apply"} {
		b, _ := json.Marshal(Request{ID: "seed", Method: method, Epoch: 1, OpID: "operation", Selector: flows.Selector{Line: "A"}})
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := Decode(b)
		if err != nil {
			return
		}
		table := flows.New(flows.Defaults(), nil)
		runtime := &runtimeFake{table: table}
		s := New(runtime, table, nil)
		s.Handle(context.Background(), Request{ID: "attach", Method: "attach", Instance: s.Instance, Epoch: 1})
		table.Apply(revision(1))
		r.Instance = s.Instance
		out := s.Handle(context.Background(), r)
		encoded, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		if !json.Valid(encoded) {
			t.Fatal("invalid response JSON")
		}
	})
}
