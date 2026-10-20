package service

import (
	"context"
	"golang.org/x/sys/windows/svc"
	"testing"
	"time"
)

func TestSCMPowerResumeReachesProgram(t *testing.T) {
	testSCMEvent(t, svc.ChangeRequest{Cmd: svc.PowerEvent, EventType: 18}, Event{Resume: true})
}

func TestSCMLogoffDispatchIgnoresExpiredCallbackPointer(t *testing.T) {
	testSCMEvent(t, svc.ChangeRequest{Cmd: svc.SessionChange, EventType: 6, EventData: 1}, Event{Logoff: true, SessionChanged: true})
}

func TestModernStandbyCallbackCycles(t *testing.T) {
	events := make(chan Event, 64)
	for range 7 {
		publishPowerEvent(events, 4)
		publishPowerEvent(events, 18)
		publishPowerEvent(events, 7)
		if e := <-events; !e.Suspend {
			t.Fatal(e)
		}
		if e := <-events; !e.Resume {
			t.Fatal(e)
		}
		if e := <-events; !e.Resume {
			t.Fatal(e)
		}
	}
}

func testSCMEvent(t *testing.T, request svc.ChangeRequest, want Event) {
	requests := make(chan svc.ChangeRequest, 1)
	updates := make(chan svc.Status, 8)
	observed := make(chan Event, 1)
	done := make(chan struct{})
	h := &handler{run: func(ctx context.Context, ready func()) error {
		ready()
		select {
		case e := <-Events(ctx):
			observed <- e
		case <-ctx.Done():
			return ctx.Err()
		}
		<-ctx.Done()
		return nil
	}}
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
				t.Fatal("program did not see power resume")
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
