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
	Native    bool
}
type Status struct {
	PID     uint32 `json:"pid"`
	Running bool   `json:"running"`
	Stopped bool   `json:"stopped"`
	// Native ExitKnown requires the main outcome AND instance-matched recovery.
	// The raw main result remains separately visible for diagnosis. A successful
	// main exit is never proof that SCM/ExecStopPost cleanup succeeded.
	ExitCode          uint32 `json:"exitCode,omitempty"`
	ExitKnown         bool   `json:"exitKnown,omitempty"`
	MainExitCode      uint32 `json:"mainExitCode,omitempty"`
	MainExitKnown     bool   `json:"mainExitKnown,omitempty"`
	Cleanup           string `json:"cleanup,omitempty"`
	LastError         string `json:"lastError,omitempty"`
	ManagerResult     string `json:"managerResult,omitempty"`
	ManagerCode       string `json:"managerCode,omitempty"`
	ManagerStatus     string `json:"managerStatus,omitempty"`
	ManagerInvocation string `json:"managerInvocation,omitempty"`
	MainExitSource    string `json:"mainExitSource,omitempty"`
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
