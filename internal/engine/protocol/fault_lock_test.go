package protocol

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// A restart fault may wait for a registrar ACK. The child's private pump
// handles status before that ACK, so status must remain callable while the
// fault is running. This reproduces the wait cycle without launching anything.
func TestFaultDoesNotHoldProtocolLockAcrossRegistrarWait(t *testing.T) {
	s, _, req := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	pumpDone := make(chan struct{})
	var epoch uint64
	var renewed Reply
	s.TestFault = func(ctx context.Context, _ json.RawMessage) (any, error) {
		go func() {
			_, _, _, _, epoch = s.Supervision()
			renewed = s.Handle(ctx, req("renew"))
			close(pumpDone) // the private pump can now consume the registrar ACK
		}()
		select {
		case <-pumpDone:
			return true, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	reply := s.Handle(ctx, req("testFault"))
	// Even the failing implementation releases its mutex when the fault's
	// deadline expires. Join its worker before reporting the regression.
	select {
	case <-pumpDone:
	case <-time.After(time.Second):
		t.Fatal("private status worker did not join")
	}
	if reply.Error != "" || renewed.Error != "" || epoch != 1 {
		t.Fatalf("fault blocked private status/renewal and its own ACK: fault=%+v renew=%+v epoch=%d", reply, renewed, epoch)
	}
}
