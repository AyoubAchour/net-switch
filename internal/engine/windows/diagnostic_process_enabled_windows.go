//go:build windows && (acceptance || netswitch_handlecheck)

package winengine

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/AyoubAchour/net-switch/internal/platform/worker"
	"golang.org/x/sys/windows"
)

// Only acceptance/handle-trace builds contain process-based evidence readers.
const diagnosticProcesses = true

func readPortConfiguration(ctx context.Context) ([]portTemplate, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	value, err := (worker.Supervisor{Executable: exe}).Once(ctx, "tcp-port-configuration", nil)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var config []portTemplate
	err = json.Unmarshal(b, &config)
	return config, err
}

// No breakaway: a supervised one-process child must refuse this diagnostic.
// Trace fixtures that need it use the standalone acceptance runtime.
func runNetsh(ctx context.Context, args ...string) reservationCommandResult {
	result := reservationCommandResult{Command: "netsh " + strings.Join(args, " ")}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		result.Error = err.Error()
		return result
	}
	ctx, cancel := context.WithTimeout(ctx, reservationCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(system, "netsh.exe"), args...)
	cmd.Dir = system
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	cmd.WaitDelay = time.Second
	var output boundedOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	began := time.Now()
	err = cmd.Run()
	result.Millis = time.Since(began).Milliseconds()
	result.Output, result.Truncated = string(output.data), output.truncated
	if err != nil {
		result.Error = errors.Join(err, ctx.Err()).Error()
	}
	return result
}
