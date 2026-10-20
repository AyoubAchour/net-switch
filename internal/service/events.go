package service

import (
	"context"
	"errors"
)

var ErrRestart = errors.New("service restart requested; preserve routing")

type Event struct {
	Resume  bool
	Logoff  bool
	Session uint32
}
type eventsKey struct{}

func Events(ctx context.Context) <-chan Event {
	ch, _ := ctx.Value(eventsKey{}).(<-chan Event)
	return ch
}
func eventContext(ctx context.Context) (context.Context, chan Event) {
	ch := make(chan Event, 64)
	return context.WithValue(ctx, eventsKey{}, (<-chan Event)(ch)), ch
}
