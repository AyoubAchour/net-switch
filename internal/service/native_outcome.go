package service

import (
	"fmt"
	"path/filepath"

	"github.com/AyoubAchour/net-switch/internal/engine/host"
)

// NativeEngineInstalled reports whether the installed engine service is the
// native one. The installation records this with the service, so Control can
// choose the engine's transport dialect before it has spoken to it.
func NativeEngineInstalled() (bool, error) {
	data, err := nativeStateDirectory()
	return data != "", err
}

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
	if state.MainExitKnown {
		state.MainExitSource = "manager"
	}
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
	if state.LastError == "" && outcome.Child != nil {
		state.LastError = outcome.Child.Error
	}
	if state.ManagerBootID != "" && state.ManagerBootID != outcome.BootID {
		state.Cleanup = "unknown"
		state.LastError = "native cleanup belongs to another or unknown boot"
		return state
	}
	if state.ManagerInvocation != "" && state.ManagerInvocation != outcome.InvocationID {
		state.Cleanup = "unknown"
		state.LastError = "native cleanup belongs to another service invocation"
		return state
	}
	// A newly loaded, never-run unit has code 0 and no invocation. Only then
	// use the manager result retained by this native instance's ExecStopPost.
	// Never replace a signal, another invocation, or a live manager result.
	if !state.MainExitKnown && state.ManagerCode == "0" && state.ManagerStatus == "0" && state.ManagerInvocation == "" && state.ManagerResult == "success" && outcome.Systemd != nil {
		if state.ManagerBootID == "" || outcome.BootID == "" {
			state.LastError = "retained native exit has no matching boot identity"
			return state
		}
		state.MainExitCode, state.MainExitKnown = outcome.Systemd.ExitCode()
		state.MainExitSource = "systemd-stop-post"
		state.ManagerResult = outcome.Systemd.Result
		if !state.MainExitKnown && state.LastError == "" {
			state.LastError = fmt.Sprintf("retained main result has no exit code: code=%q status=%q result=%q", outcome.Systemd.Code, outcome.Systemd.Status, outcome.Systemd.Result)
		}
	}
	incomplete := outcome.Child != nil && (!outcome.Child.Completed || outcome.Child.Forced || state.MainExitKnown && outcome.Child.Code != state.MainExitCode)
	if outcome.State == "failed" || state.MainExitKnown && incomplete && (state.MainExitCode == 0 || state.MainExitCode == 3) || (state.MainExitKnown && state.MainExitCode == 0 && state.ManagerResult != "" && state.ManagerResult != "success") {
		state.ExitKnown, state.ExitCode = true, 1
		if state.LastError == "" {
			if incomplete {
				state.LastError = "native child has no completed, unforced outcome"
			} else {
				state.LastError = "service cleanup failed: " + state.ManagerResult
			}
		}
		return state
	}
	if outcome.State == "complete" {
		state.ExitKnown, state.ExitCode = state.MainExitKnown, state.MainExitCode
	}
	if state.LastError == "" && outcome.State != "complete" {
		state.LastError = fmt.Sprintf("native cleanup is %s for %s", outcome.State, record.Instance)
	}
	if state.LastError == "" && !state.MainExitKnown {
		state.LastError = fmt.Sprintf("main exit code unavailable: manager code=%q status=%q invocation=%q", state.ManagerCode, state.ManagerStatus, state.ManagerInvocation)
	}
	return state
}
