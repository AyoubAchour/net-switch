// Package service contains the OS service-manager boundary. It never launches
// an engine as a child of Control.
package service

import (
	"context"
	"time"
)

const Control = "NetSwitch"
const Engine = "NetSwitchEngine"

type Program func(context.Context, func()) error
type Config struct {
	Directory string
	Data      string
	Owner     string
}
type Status struct {
	PID     uint32 `json:"pid"`
	Running bool   `json:"running"`
	Stopped bool   `json:"stopped"`
	// ExitCode is meaningful only when ExitKnown and Stopped are both true.
	// A signal/SCM infrastructure failure never masquerades as engine exit 3.
	ExitCode  uint32 `json:"exitCode,omitempty"`
	ExitKnown bool   `json:"exitKnown,omitempty"`
}

// ExitCode accepts only a direct, completed outcome. In particular, joining
// an adapter-loss outcome with a late cleanup failure must return failure 1.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	if outcome, ok := err.(interface{ EngineExitCode() int }); ok {
		if code := outcome.EngineExitCode(); code > 0 && code < 256 {
			return code
		}
	}
	return 1
}

func WaitStopped(ctx context.Context, name string) error {
	for {
		s, err := Query(name)
		if err != nil {
			return err
		}
		if s.Stopped {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}
