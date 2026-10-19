package protocol

import (
	"context"
	"testing"
)

func TestEngineAssignsEpochs(t *testing.T) {
	s, _, req := setup(t)
	r := req("attach")
	r.Epoch = 999999
	if s.Handle(context.Background(), r).Error == "" || s.epoch != 1 {
		t.Fatal("Control picked its own epoch")
	}
	r.Epoch = 0
	if v := call(t, s, r).Result.(map[string]any)["epoch"]; v != uint64(2) {
		t.Fatal(v)
	}
	if s.Handle(context.Background(), req("renew")).Error == "" {
		t.Fatal("previous epoch remains valid")
	}
}
