//go:build windows

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

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
		{"clean adapter loss", lost, 3},
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

// Run the test executable itself, never the engine's runtime/service path.
// An actual unrecovered panic verifies the runtime status rather than assuming
// it equals a test constant. The other children call main's real exit mapping.
func TestEngineProcessExitOutcomes(t *testing.T) {
	lost := &winengine.AdapterLostError{Cause: errors.New("adapter removed")}
	if mode := os.Getenv("NETSWITCH_EXIT_CONTRACT_CHILD"); mode != "" {
		switch mode {
		case "panic":
			panic("exit-contract panic")
		case "ordinary":
			os.Exit(exitCode(errors.New("ordinary failure")))
		case "loss":
			os.Exit(exitCode(lost))
		case "joined":
			os.Exit(exitCode(errors.Join(lost, errors.New("cleanup failure"))))
		case "stop":
			os.Exit(exitCode(nil))
		default:
			t.Fatalf("unknown exit contract child %q", mode)
		}
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mode string
		want int
	}{
		{"panic", 2}, {"ordinary", 1}, {"loss", 3}, {"joined", 1}, {"stop", 0},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, self, "-test.run=^TestEngineProcessExitOutcomes$")
			cmd.Env = append(os.Environ(), "NETSWITCH_EXIT_CONTRACT_CHILD="+tc.mode, "GOTRACEBACK=single")
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			output, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("exit probe timed out: %v", ctx.Err())
			}
			code := 0
			if err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Fatal(err)
				}
				code = exit.ExitCode()
			}
			if code != tc.want {
				t.Fatalf("process exit=%d want=%d output=%s", code, tc.want, output)
			}
			if tc.mode == "panic" && (!strings.Contains(string(output), "panic: exit-contract panic") || code == winengine.AdapterLostExitCode) {
				t.Fatalf("panic confused with clean adapter loss: code=%d output=%s", code, output)
			}
		})
	}
}
