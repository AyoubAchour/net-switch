// Package crashnet gives every owned goroutine the same fatal-error boundary.
package crashnet

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"time"
)

type Net struct {
	once   sync.Once
	log    func(string)
	stop   func(context.Context) error
	failed chan error
}

func New(log func(string), stop func(context.Context) error) *Net {
	return &Net{log: log, stop: stop, failed: make(chan error, 1)}
}

func (n *Net) Failures() <-chan error { return n.failed }

// Defer Recover directly in the goroutine being guarded. Cleanup runs after
// its stack unwinds, so a held lifecycle/apply mutex cannot deadlock shutdown.
func (n *Net) Recover(where string) {
	if value := recover(); value != nil {
		if n == nil {
			panic(value)
		}
		n.Report(where, value)
	}
}

func (n *Net) Report(where string, value any) {
	n.once.Do(func() {
		err := fmt.Errorf("%s panicked: %v", where, value)
		n.log(fmt.Sprintf("fatal control error: %v\n%s", err, debug.Stack()))
		go func() {
			defer func() {
				if p := recover(); p != nil {
					n.failed <- fmt.Errorf("%w; crash cleanup panicked: %v", err, p)
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if failure := n.stop(ctx); failure != nil {
				n.log("crash cleanup could not stop routing: " + failure.Error())
				err = fmt.Errorf("%w; stop routing: %v", err, failure)
			}
			n.failed <- err
		}()
	})
}
