package service

import "testing"

func TestEventQueueNeverDropsTheResumeAfterABurst(t *testing.T) {
	q := NewEventQueue()
	q.Publish(Event{Suspend: true})
	// The old 64-slot channel dropped everything after this burst,
	// including the resume, which left new starts paused for good.
	for range 1000 {
		q.Publish(Event{SessionChanged: true})
	}
	q.Publish(Event{Logoff: true, SessionChanged: true})
	q.Publish(Event{Resume: true})
	select {
	case <-q.Ready():
	default:
		t.Fatal("consumer was not woken")
	}
	got := q.Take()
	want := []Event{{SessionChanged: true, Logoff: true}, {Suspend: true}, {Resume: true}}
	if len(got) != len(want) {
		t.Fatal(got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatal(got)
		}
	}
	if rest := q.Take(); len(rest) != 0 {
		t.Fatal("Take did not clear the queue", rest)
	}
}

func TestEventQueueKeepsTheLastPowerTransitions(t *testing.T) {
	for _, test := range []struct {
		publish []bool // true = suspend
		want    []bool
	}{
		{[]bool{true, false, true}, []bool{false, true}},
		{[]bool{true, false, true, false}, []bool{true, false}},
		{[]bool{false, false, false}, []bool{false}},
		{[]bool{true, true}, []bool{true}},
	} {
		q := NewEventQueue()
		for _, suspend := range test.publish {
			q.Publish(Event{Suspend: suspend, Resume: !suspend})
		}
		got := q.Take()
		if len(got) != len(test.want) {
			t.Fatal(test.publish, got)
		}
		for i, suspend := range test.want {
			if got[i].Suspend != suspend || got[i].Resume == suspend {
				t.Fatal(test.publish, got)
			}
		}
	}
}

func TestNilEventQueueIsQuiet(t *testing.T) {
	var q *EventQueue
	if q.Ready() != nil || q.Take() != nil {
		t.Fatal("nil queue produced events")
	}
}
