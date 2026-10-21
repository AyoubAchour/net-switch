//go:build windows

package main

import (
	"errors"
	"testing"

	winengine "github.com/AyoubAchour/net-switch/internal/engine/windows"
)

func TestMainUsesOnlyDirectCompletedEngineExitOutcome(t *testing.T) {
	lost := &winengine.AdapterLostError{Cause: errors.New("adapter removed")}
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{"ordinary stop", nil, 0},
		{"clean adapter loss", lost, 2},
		{"ordinary failure", errors.New("cleanup failed"), 1},
		{"loss joined with failure", errors.Join(lost, errors.New("late close failed")), 1},
		{"wrapped loss", errors.Join(lost), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := exitCode(tc.err); got != tc.want {
				t.Fatalf("main exitCode=%d want=%d", got, tc.want)
			}
		})
	}
}
