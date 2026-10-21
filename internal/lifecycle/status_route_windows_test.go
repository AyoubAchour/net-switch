package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/localipc"
	"golang.org/x/sys/windows"
)

// The fallback must recognise the exact errors CreateFile returns for a pipe
// ACL denial and for a stopped service, not just the portable sentinels.
func TestStatusReaderFallbackMatchesPipeErrors(t *testing.T) {
	if !errors.Is(windows.ERROR_ACCESS_DENIED, fs.ErrPermission) {
		t.Fatal("ERROR_ACCESS_DENIED is not a permission error")
	}
	for _, refusal := range []error{windows.ERROR_ACCESS_DENIED, windows.ERROR_FILE_NOT_FOUND} {
		s := newRouteServer(t, localipc.Peer{User: "S-1-5-21-1-2-3-1002", PID: 45}, false)
		s.refuse["desktop"] = fmt.Errorf("open: %w", refusal)
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
