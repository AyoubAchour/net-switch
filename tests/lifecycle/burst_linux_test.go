package lifecycle_test

import (
	"errors"
	"fmt"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	"net"
	"os"
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
	// Prove the cap exists rather than only that Control survived: of ten
	// connections held by this one user, the server must close all but two
	// at once. Without admission limits all ten would stay open.
	var held []net.Conn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	for range 10 {
		c, err := net.DialTimeout("unix", localipc.DefaultPath("status"), time.Second)
		if err != nil {
			return err
		}
		held = append(held, c)
	}
	open, closed := 0, 0
	deadline := time.Now().Add(1500 * time.Millisecond)
	for _, c := range held {
		c.SetReadDeadline(deadline)
		if _, err := c.Read(make([]byte, 1)); err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
			closed++
		} else {
			open++
		}
	}
	if open > 2 || closed < 8 {
		return fmt.Errorf("per-user public socket cap not enforced: open=%d closed=%d", open, closed)
	}
	fmt.Printf("per-user public cap: %d of 10 held connections stayed open, %d closed at admission\n", open, closed)
	return nil
}
