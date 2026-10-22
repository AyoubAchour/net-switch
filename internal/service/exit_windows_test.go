package service

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/sys/windows/svc"
)

func TestSCMRetainsOnlyDirectCompletedExitOutcome(t *testing.T) {
	for _, failure := range []error{completedExit(3), errors.Join(completedExit(3), errors.New("late close")), nil} {
		h := &handler{run: func(context.Context, func()) error { return failure }}
		specific, code := h.Execute(nil, make(chan svc.ChangeRequest), make(chan svc.Status, 8))
		if code != uint32(ExitCode(failure)) || specific != (failure != nil) {
			t.Fatalf("SCM outcome specific=%t code=%d for %v", specific, code, failure)
		}
	}
}
