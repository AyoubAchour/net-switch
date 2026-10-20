package lifecycle_test

import (
	"fmt"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

func disconnectBurst() error {
	var opened atomic.Uint64
	var workers sync.WaitGroup
	until := time.Now().Add(5 * time.Second)
	for range 8 {
		workers.Go(func() {
			for time.Now().Before(until) {
				c, err := net.DialTimeout("unix", localipc.DefaultPath("status"), time.Second)
				if err == nil {
					c.Close()
					opened.Add(1)
				}
			}
		})
	}
	workers.Wait()
	if opened.Load() < 500 {
		return fmt.Errorf("only %d public socket connections", opened.Load())
	}
	fmt.Printf("raw other-user Unix connect/close burst: %d connections\n", opened.Load())
	return nil
}
