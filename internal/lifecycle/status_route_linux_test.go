package lifecycle

import (
	"context"
	"fmt"
	"syscall"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/localipc"
)

// The fallback must recognise the exact errors connect(2) returns for the
// owner socket's ACL and for a stopped service.
func TestStatusReaderFallbackMatchesSocketErrors(t *testing.T) {
	for _, refusal := range []error{syscall.EACCES, syscall.ENOENT, syscall.ECONNREFUSED} {
		s := newRouteServer(t, localipc.Peer{User: "1002", PID: 45}, false)
		s.refuse["desktop"] = fmt.Errorf("dial unix: %w", refusal)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		rpc, err := ConnectStatus(ctx)
		cancel()
		if err != nil {
			t.Fatal(refusal, err)
		}
		rpc.Close()
		if got := s.dials(); got != "desktop,status" {
			t.Fatal(refusal, "unexpected dial order", got)
		}
	}
}
