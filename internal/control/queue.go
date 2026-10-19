package control

import (
	"context"
	"fmt"
	"github.com/AyoubAchour/net-switch/internal/crashnet"
)

type work struct {
	ctx  context.Context
	run  func() error
	done chan error
}

// Queue owns its work list in one goroutine. An abandoned caller never leaves a
// worker blocked on delivery, and a failed item cannot poison later requests.
type Queue struct {
	jobs chan work
	stop chan struct{}
}

func newQueue(ctx context.Context, net ...*crashnet.Net) *Queue {
	q := &Queue{make(chan work), make(chan struct{})}
	go func() {
		defer close(q.stop)
		for {
			select {
			case <-ctx.Done():
				return
			case w := <-q.jobs:
				if err := w.ctx.Err(); err != nil {
					w.done <- err
					continue
				}
				func() {
					defer func() {
						if p := recover(); p != nil {
							if len(net) != 0 && net[0] != nil {
								net[0].Report("control queue", p)
							}
							w.done <- fmt.Errorf("queued operation panicked: %v", p)
						}
					}()
					w.done <- w.run()
				}()
			}
		}
	}()
	return q
}
func (q *Queue) Do(ctx context.Context, f func() error) error {
	w := work{ctx, f, make(chan error, 1)}
	select {
	case q.jobs <- w:
	case <-ctx.Done():
		return ctx.Err()
	case <-q.stop:
		return context.Canceled
	}
	select {
	case err := <-w.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-q.stop:
		return context.Canceled
	}
}
