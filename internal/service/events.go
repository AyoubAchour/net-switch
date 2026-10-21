package service

import (
	"context"
	"errors"
	"sync"
)

var ErrRestart = errors.New("service restart requested; preserve routing")

type Event struct {
	Suspend        bool
	SessionChanged bool
	Resume         bool
	Logoff         bool
	Session        uint32
}

// EventQueue holds service notifications as state, not as a bounded list. A
// consumer that falls behind still sees every session change and the latest
// power transition, so a burst can never drop the resume that ends a pause.
type EventQueue struct {
	mu      sync.Mutex
	power   []bool // pending transitions in order; true means suspend
	session bool
	logoff  bool
	ready   chan struct{}
}

func NewEventQueue() *EventQueue { return &EventQueue{ready: make(chan struct{}, 1)} }

// Publish records e and wakes the consumer. It never blocks.
func (q *EventQueue) Publish(e Event) {
	q.mu.Lock()
	if e.SessionChanged || e.Logoff {
		q.session = true
		q.logoff = q.logoff || e.Logoff
	}
	// A notification is either a suspend or a resume. Repeats add nothing,
	// and only the last two transitions matter: the final state, and a
	// resume before a newer suspend, which still rechecks the owner.
	if suspend := e.Suspend; suspend || e.Resume {
		if n := len(q.power); n == 0 || q.power[n-1] != suspend {
			q.power = append(q.power, suspend)
			if len(q.power) > 2 {
				q.power = q.power[len(q.power)-2:]
			}
		}
	}
	q.mu.Unlock()
	select {
	case q.ready <- struct{}{}:
	default:
	}
}

// Ready is signalled after Publish. A nil queue never becomes ready.
func (q *EventQueue) Ready() <-chan struct{} {
	if q == nil {
		return nil
	}
	return q.ready
}

// Take returns and clears the pending events: one session event first, then
// the power transitions in the order they happened.
func (q *EventQueue) Take() []Event {
	if q == nil {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	var out []Event
	if q.session {
		out = append(out, Event{SessionChanged: true, Logoff: q.logoff})
	}
	for _, suspend := range q.power {
		out = append(out, Event{Suspend: suspend, Resume: !suspend})
	}
	q.power, q.session, q.logoff = nil, false, false
	return out
}

type eventsKey struct{}

// Events returns the service's notifications, or nil outside a service that
// delivers them.
func Events(ctx context.Context) *EventQueue {
	q, _ := ctx.Value(eventsKey{}).(*EventQueue)
	return q
}

func eventContext(ctx context.Context) (context.Context, *EventQueue) {
	q := NewEventQueue()
	return context.WithValue(ctx, eventsKey{}, q), q
}
