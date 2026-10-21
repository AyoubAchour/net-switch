package service

import (
	"context"
	"errors"
	"golang.org/x/sys/windows/svc"
	"testing"
	"time"
)

func TestSCMPowerResumeReachesProgram(t *testing.T) {
	testSCMEvent(t, nil, svc.ChangeRequest{Cmd: svc.PowerEvent, EventType: 18}, Event{Resume: true})
}

func TestSCMLogoffDispatchIgnoresExpiredCallbackPointer(t *testing.T) {
	testSCMEvent(t, nil, svc.ChangeRequest{Cmd: svc.SessionChange, EventType: 6, EventData: 1}, Event{Logoff: true, SessionChanged: true})
}

func TestFailedPowerSubscriptionFallsBackToSCMEvents(t *testing.T) {
	var warned error
	h := &handler{name: "test", power: func(*EventQueue) (func(), error) { return nil, errors.New("registration refused") }, warn: func(_ string, err error) { warned = err }}
	testSCMEvent(t, h, svc.ChangeRequest{Cmd: svc.PowerEvent, EventType: 7}, Event{Resume: true})
	if warned == nil {
		t.Fatal("failed power subscription was not logged")
	}
}

func TestModernStandbyCallbackCycles(t *testing.T) {
	events := NewEventQueue()
	for range 7 {
		publishPowerEvent(events, 4)
		publishPowerEvent(events, 18)
		publishPowerEvent(events, 7)
		got := events.Take()
		if len(got) != 2 || !got[0].Suspend || !got[1].Resume {
			t.Fatal(got)
		}
	}
}

func testSCMEvent(t *testing.T, h *handler, request svc.ChangeRequest, want Event) {
	requests := make(chan svc.ChangeRequest, 1)
	updates := make(chan svc.Status, 8)
	observed := make(chan Event, 1)
	done := make(chan struct{})
	if h == nil {
		h = &handler{}
	}
	h.run = func(ctx context.Context, ready func()) error {
		ready()
		select {
		case <-Events(ctx).Ready():
			observed <- Events(ctx).Take()[0]
		case <-ctx.Done():
			return ctx.Err()
		}
		<-ctx.Done()
		return nil
	}
	go func() { h.Execute(nil, requests, updates); close(done) }()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for {
		select {
		case s := <-updates:
			if s.State != svc.Running {
				continue
			}
			if s.Accepts&svc.AcceptPowerEvent == 0 {
				t.Fatal("SCM will not deliver resume")
			}
			requests <- request
			select {
			case event := <-observed:
				if event != want {
					t.Fatal(event)
				}
			case <-timer.C:
				t.Fatal("program did not see the event")
			}
			requests <- svc.ChangeRequest{Cmd: svc.Stop}
			select {
			case <-done:
				return
			case <-timer.C:
				t.Fatal("service did not stop")
			}
		case <-timer.C:
			t.Fatal("service did not become ready")
		}
	}
}
