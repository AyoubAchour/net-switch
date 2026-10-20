// Package service contains the OS service-manager boundary. It never launches
// an engine as a child of Control.
package service

import "context"

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
}
