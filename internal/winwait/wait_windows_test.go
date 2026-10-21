//go:build windows

package winwait

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	stackMoveChildEnv = "NETSWITCH_WINWAIT_STACK_MOVE"
	stackMoveMarker   = "WINWAIT STACK MOVE "
	// 3,000 frames of a few dozen bytes cross the 8, 16, 32 and 64 KiB stack
	// sizes, each at every frame offset the step allows.
	stackMoveDepth = 3000
)

func TestMain(m *testing.M) {
	if mode := os.Getenv(stackMoveChildEnv); mode != "" {
		os.Exit(runStackMoveChild(mode))
	}
	os.Exit(m.Run())
}

func TestWaitForMultipleObjects(t *testing.T) {
	signalled, err := windows.CreateEvent(nil, 1, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(signalled)
	idle, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(idle)

	if r, err := WaitForMultipleObjects([]windows.Handle{idle, signalled}, false, 0); err != nil || r != windows.WAIT_OBJECT_0+1 {
		t.Fatalf("wait any = %d, %v; want WAIT_OBJECT_0+1", r, err)
	}
	if r, err := WaitForMultipleObjects([]windows.Handle{idle, signalled}, true, 0); err != nil || r != uint32(windows.WAIT_TIMEOUT) {
		t.Fatalf("wait all = %d, %v; want WAIT_TIMEOUT", r, err)
	}
	if r, err := WaitForMultipleObjects(nil, false, 0); !errors.Is(err, syscall.EINVAL) || r != windows.WAIT_FAILED {
		t.Fatalf("empty wait = %d, %v; want WAIT_FAILED, EINVAL", r, err)
	}
	if r, err := WaitForMultipleObjects(make([]windows.Handle, maximumWaitObjects+1), false, 0); !errors.Is(err, syscall.EINVAL) || r != windows.WAIT_FAILED {
		t.Fatalf("oversized wait = %d, %v; want WAIT_FAILED, EINVAL", r, err)
	}
	// A closed handle is reported by the kernel, with its own error.
	closed, err := windows.CreateEvent(nil, 1, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	windows.CloseHandle(closed)
	if r, err := WaitForMultipleObjects([]windows.Handle{signalled, closed}, false, 0); !errors.Is(err, windows.ERROR_INVALID_HANDLE) || r != windows.WAIT_FAILED {
		t.Fatalf("closed-handle wait = %d, %v; want WAIT_FAILED, ERROR_INVALID_HANDLE", r, err)
	}
}

type stackMoveReport struct {
	Mode       string         `json:"mode"`
	Arch       string         `json:"arch"`
	Trials     int            `json:"trials"`
	Moved      int            `json:"moved"`
	Failed     int            `json:"failed"`
	FailedMove int            `json:"failedAfterMove"` // failures in trials whose stack moved
	FailedStay int            `json:"failedInPlace"`   // failures without a move: not this hazard
	OnStack    int            `json:"arrayOnStack"`
	FirstDepth int            `json:"firstFailureDepth"`
	Errors     map[string]int `json:"errors"`
	Results    map[string]int `json:"wrongResults"`
}

// TestWaitArrayStackMove reproduces the x/sys hazard deterministically and
// proves this helper closes it. Each child process runs with GODEBUG=efence=1,
// which makes the runtime decommit a goroutine's old stack as soon as the
// stack is copied. Every trial starts a fresh goroutine, descends a different
// number of frames and then waits on a two-handle array on that stack, so
// some trials grow the stack exactly inside the wait wrapper. The x/sys path
// then passes the kernel an address in the decommitted stack; this helper
// converts the address only inside the non-splitting syscall.
func TestWaitArrayStackMove(t *testing.T) {
	if raceEnabled {
		// efence decommits stacks the race runtime's shadow memory still
		// covers; the race child faults inside the race runtime itself (run
		// 39559172829). The non-race jobs on both architectures run this.
		t.Skip("GODEBUG=efence cannot run under the race detector")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	run := func(mode string) (stackMoveReport, int, string, time.Duration) {
		cmd := exec.Command(exe)
		cmd.Env = append(os.Environ(), stackMoveChildEnv+"="+mode, "GODEBUG=efence=1", "GOTRACEBACK=single")
		began := time.Now()
		out, err := cmd.CombinedOutput()
		elapsed := time.Since(began)
		code := 0
		if exit := (*exec.ExitError)(nil); errors.As(err, &exit) {
			code = exit.ExitCode()
		} else if err != nil {
			t.Fatalf("%s child: %v", mode, err)
		}
		var report stackMoveReport
		for _, line := range strings.Split(string(out), "\n") {
			if rest, ok := strings.CutPrefix(strings.TrimSpace(line), stackMoveMarker); ok {
				if err := json.Unmarshal([]byte(rest), &report); err != nil {
					t.Fatalf("%s child report: %v", mode, err)
				}
			}
		}
		return report, code, string(out), elapsed
	}

	fixed, code, out, elapsed := run("helper")
	t.Logf("helper child exit=%d elapsed=%s report=%+v", code, elapsed.Round(time.Millisecond), fixed)
	if code != 0 || fixed.Mode != "helper" {
		t.Fatalf("helper child exit=%d; output:\n%s", code, tail(out))
	}
	if fixed.Trials != stackMoveDepth+1 || fixed.Moved == 0 || fixed.OnStack != fixed.Trials {
		t.Fatalf("helper sweep did not move a stack-resident array around the call: %+v", fixed)
	}
	if fixed.Failed != 0 {
		t.Fatalf("helper wait failed after a stack move: %+v", fixed)
	}

	// Negative control: the unchanged x/sys wrapper must fail on the same
	// sweep, either with an error from the kernel or with an access violation
	// when KernelBase reads the decommitted array. If it never fails, the
	// sweep has no power and the helper's pass above proves nothing.
	legacy, code, out, elapsed := run("xsys")
	// Attribute the failure to this hazard, not to any crash. A returned
	// failure must come from a trial whose stack moved, with none in place.
	// A crash must be an access violation at exactly the array address that
	// x/sys handed to the kernel, read from the crashing goroutine's trace.
	faultAddress, passedAddress := crashAddresses(out)
	violation := code != 0 && faultAddress != "" && faultAddress == passedAddress
	reproduced := (legacy.FailedMove != 0 && legacy.FailedStay == 0) || violation
	t.Logf("x/sys child exit=%d elapsed=%s fault_address=%s passed_array=%s attributed_violation=%t report=%+v old_would_pass=%t",
		code, elapsed.Round(time.Millisecond), faultAddress, passedAddress, violation, legacy, !reproduced)
	if !reproduced {
		t.Fatalf("x/sys wrapper did not reproduce the stack-move hazard (exit=%d); output:\n%s", code, tail(out))
	}
	if code != 0 {
		t.Logf("x/sys child crash excerpt:\n%s", tail(out))
	}
}

// crashAddresses returns the faulting address of a Go "Exception 0xc0000005"
// report and the handle-array argument of x/sys's waitForMultipleObjects frame
// in the same output, both as printed (hex). Either is empty when absent.
func crashAddresses(out string) (fault, passed string) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if fields := strings.Fields(line); fault == "" && len(fields) >= 4 && fields[0] == "Exception" && fields[1] == "0xc0000005" {
			fault = fields[3]
		}
		if rest, ok := strings.CutPrefix(line, "golang.org/x/sys/windows.waitForMultipleObjects("); ok && passed == "" {
			if args := strings.Split(rest, ","); len(args) >= 2 {
				passed = strings.TrimSuffix(strings.TrimSpace(args[1]), "?")
			}
		}
	}
	return fault, passed
}

func tail(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > 40 {
		lines = lines[:40]
	}
	return strings.Join(lines, "\n")
}

type stackMoveTrial struct {
	legacy  bool
	a, b    windows.Handle
	result  uint32
	err     error
	moved   bool
	onStack bool
}

func runStackMoveChild(mode string) int {
	if mode != "helper" && mode != "xsys" {
		fmt.Fprintln(os.Stderr, "unknown stack-move mode", mode)
		return 2
	}
	signalled, err := windows.CreateEvent(nil, 1, 1, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	idle, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	report := stackMoveReport{Mode: mode, Arch: runtime.GOARCH, FirstDepth: -1, Errors: map[string]int{}, Results: map[string]int{}}
	for depth := 0; depth <= stackMoveDepth; depth++ {
		c := &stackMoveTrial{legacy: mode == "xsys", a: signalled, b: idle}
		done := make(chan struct{})
		go func() {
			defer close(done)
			stackMoveDescend(depth, c)
		}()
		<-done
		report.Trials++
		if c.moved {
			report.Moved++
		}
		if c.onStack {
			report.OnStack++
		}
		if c.err != nil || c.result != windows.WAIT_OBJECT_0 {
			report.Failed++
			if c.moved {
				report.FailedMove++
			} else {
				report.FailedStay++
			}
			if report.FirstDepth < 0 {
				report.FirstDepth = depth
			}
			if c.err != nil {
				report.Errors[c.err.Error()]++
			} else {
				report.Results[fmt.Sprint(c.result)]++
			}
		}
	}
	b, _ := json.Marshal(report)
	fmt.Println(stackMoveMarker + string(b))
	return 0
}

//go:noinline
func stackMoveDescend(depth int, c *stackMoveTrial) {
	if depth > 0 {
		stackMoveDescend(depth-1, c)
		return
	}
	stackMoveLeaf(c)
}

//go:noinline
func stackMoveLeaf(c *stackMoveTrial) {
	// probe never escapes; its address changes only when this goroutine's
	// stack is copied. The handle array must sit beside it on the stack.
	var probe byte
	handles := [2]windows.Handle{c.a, c.b}
	before := uintptr(unsafe.Pointer(&probe))
	distance := int64(uintptr(unsafe.Pointer(&handles[0]))) - int64(before)
	c.onStack = distance > -4096 && distance < 4096
	if c.legacy {
		c.result, c.err = windows.WaitForMultipleObjects(handles[:], false, 0)
	} else {
		c.result, c.err = WaitForMultipleObjects(handles[:], false, 0)
	}
	c.moved = uintptr(unsafe.Pointer(&probe)) != before
}
