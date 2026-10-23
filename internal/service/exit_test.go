package service

import (
	"errors"
	"testing"
)

type completedExit int

func (e completedExit) Error() string       { return "completed" }
func (e completedExit) EngineExitCode() int { return int(e) }

func TestExitOutcomeMustBeDirectAndCompleted(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{
		{nil, 0}, {errors.New("failure"), 1}, {completedExit(3), 3},
		{errors.Join(completedExit(3), errors.New("late close")), 1},
		{errors.Join(completedExit(3)), 1}, {completedExit(0), 1}, {completedExit(256), 1},
	} {
		if code := ExitCode(tc.err); code != tc.want {
			t.Errorf("%v: exit %d, want %d", tc.err, code, tc.want)
		}
	}
}
