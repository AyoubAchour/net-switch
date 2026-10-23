package winengine

import (
	"context"
	"fmt"
	"testing"

	"golang.org/x/sys/windows"
)

func TestProbeUnavailableClassifiesOnlyLocalResources(t *testing.T) {
	for _, err := range []error{windows.WSAEMFILE, windows.WSAENOBUFS, windows.WSAEADDRINUSE, windows.ERROR_NOT_ENOUGH_MEMORY, windows.ERROR_OUTOFMEMORY} {
		if !probeUnavailable(fmt.Errorf("socket: %w", err)) {
			t.Fatal(err)
		}
	}
	if probeUnavailable(windows.WSAECONNREFUSED) || probeUnavailable(context.DeadlineExceeded) {
		t.Fatal("line failure treated as engine overload")
	}
}
