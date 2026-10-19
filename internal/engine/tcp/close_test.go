package tcp

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestConcurrentCleanupClosesEndpointOnce(t *testing.T) {
	var closed atomic.Int32
	closeEndpoint := sync.OnceFunc(func() { closed.Add(1) })
	c := &onceCloseConn{close: closeEndpoint}
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() { c.Close() })
		wg.Go(closeEndpoint)
	}
	wg.Wait()
	if got := closed.Load(); got != 1 {
		t.Fatalf("endpoint closed %d times", got)
	}
}
