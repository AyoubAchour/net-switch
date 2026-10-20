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
