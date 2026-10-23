//go:build windows && !acceptance && !netswitch_handlecheck

package winengine

import (
	"context"
	"errors"
)

const diagnosticProcesses = false

var errDiagnosticProcessesDisabled = errors.New("process-based port diagnostics are disabled in product builds")

func readPortConfiguration(context.Context) ([]portTemplate, error) {
	return nil, errDiagnosticProcessesDisabled
}
func runNetsh(context.Context, ...string) reservationCommandResult {
	return reservationCommandResult{Error: errDiagnosticProcessesDisabled.Error()}
}
