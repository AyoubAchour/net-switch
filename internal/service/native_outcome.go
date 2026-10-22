package service

import (
	"fmt"
	"path/filepath"

	"github.com/AyoubAchour/net-switch/internal/engine/host"
)

func nativeOutcome(name string, state Status) Status {
	if name != Engine || !state.Stopped {
		return state
	}
	data, err := nativeStateDirectory()
	if data == "" && err == nil {
		return state
	} // M2 stand-in or never installed
	return readNativeOutcome(data, state, err)
}

func readNativeOutcome(data string, state Status, err error) Status {
	state.MainExitCode, state.MainExitKnown = state.ExitCode, state.ExitKnown
	state.ExitKnown = false
	state.Cleanup = "pending"
	if err != nil {
		state.LastError = err.Error()
		return state
	}
	record, err := host.ReadRecord(filepath.Join(data, "engine-state.json"))
	if err != nil {
		state.LastError = "native exit state: " + err.Error()
		return state
	}
	outcome, err := host.ReadOutcome(data, record.Instance)
	if err != nil {
		state.LastError = "native cleanup result: " + err.Error()
		return state
	}
	state.Cleanup, state.LastError = outcome.State, outcome.Error
	if outcome.State == "failed" || (state.MainExitKnown && state.MainExitCode == 0 && state.ManagerResult != "" && state.ManagerResult != "success") {
		state.ExitKnown, state.ExitCode = true, 1
		if state.LastError == "" {
			state.LastError = "service cleanup failed: " + state.ManagerResult
		}
		return state
	}
	if outcome.State == "complete" {
		state.ExitKnown, state.ExitCode = state.MainExitKnown, state.MainExitCode
	}
	if state.LastError == "" && outcome.State != "complete" {
		state.LastError = fmt.Sprintf("native cleanup is %s for %s", outcome.State, record.Instance)
	}
	return state
}
