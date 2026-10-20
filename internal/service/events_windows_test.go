package service

import (
	"context"
	"golang.org/x/sys/windows/svc"
	"testing"
	"time"
)

func TestSCMPowerResumeReachesProgram(t *testing.T) {
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
			requests <- svc.ChangeRequest{Cmd: svc.PowerEvent, EventType: 18}
			select {
			case event := <-observed:
				if !event.Resume {
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
