//go:build windows

package winchild

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

func hosted() bool {
	return os.Getenv("GITHUB_ACTIONS") == "true" && os.Getenv("RUNNER_ENVIRONMENT") == "github-hosted" && os.Getenv("NETSWITCH_CHILD_CI") == "1"
}

func TestMain(m *testing.M) {
	if len(os.Args) >= 3 && os.Args[1] == "--guarded-child-fixture" {
		if !hosted() {
			os.Exit(99)
		}
		switch os.Args[2] {
		case "create-window", "create-window-uncontained":
			report := func(pid uint32) {
				fmt.Println(pid)
				var b [1]byte
				os.Stdin.Read(b[:])
			}
			if os.Args[2] == "create-window-uncontained" {
				// Negative control: the old create-then-assign gap, before the
				// assignment could run. Only a disposable hosted helper does this.
				exe, _ := os.Executable()
				c := exec.Command(exe, "--guarded-child-fixture", "hold")
				c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED | windows.DETACHED_PROCESS}
				if err := c.Start(); err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(96)
				}
				report(uint32(c.Process.Pid))
				c.Process.Kill()
				c.Wait()
			} else {
				afterCreate = func(pi windows.ProcessInformation) { report(pi.ProcessId) }
				p, err := StartSelf(Options{Args: []string{"--guarded-child-fixture", "hold"}, Env: os.Environ()})
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(95)
				}
				p.Close()
			}
		case "exit":
			code, err := strconv.ParseUint(os.Args[3], 0, 32)
			if err != nil {
				os.Exit(98)
			}
			os.Exit(int(code))
		case "parent":
			fmt.Println(CheckRegistrarParent() == nil)
		case "hold":
			fmt.Println("READY")
			var b [1]byte
			os.Stdin.Read(b[:])
		case "flood":
			go func() {
				for {
					os.Stdout.Write(make([]byte, 64<<10))
				}
			}()
			for {
				os.Stderr.Write(make([]byte, 64<<10))
			}
		default:
			os.Exit(97)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestHostedDeathAtCreateReturnClosesTheOldOrphanWindow(t *testing.T) {
	if !hosted() {
		t.Skip("creation death proofs run only on hosted runners")
	}
	for _, mode := range []string{"create-window-uncontained", "create-window"} {
		t.Run(mode, func(t *testing.T) {
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			c := exec.CommandContext(ctx, exe, "--guarded-child-fixture", mode)
			input, err := c.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			output, err := c.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			c.Stderr = os.Stderr
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			t.Cleanup(func() {
				c.Process.Kill()
				input.Close()
				if !waited {
					c.Wait()
				}
			})
			line, err := bufio.NewReader(output).ReadString('\n')
			if err != nil {
				t.Fatal("creation marker", err)
			}
			pid, err := strconv.ParseUint(strings.TrimSpace(line), 10, 32)
			if err != nil {
				t.Fatal(line, err)
			}
			child, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, uint32(pid))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				windows.TerminateProcess(child, 1)
				windows.WaitForSingleObject(child, 5000)
				windows.CloseHandle(child)
			})
			if state, err := windows.WaitForSingleObject(child, 0); err != nil || state != uint32(windows.WAIT_TIMEOUT) {
				t.Fatal("creation child not live", state, err)
			}
			if err := c.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			c.Wait()
			waited = true
			state, err := windows.WaitForSingleObject(child, 500)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "create-window-uncontained" {
				if state != uint32(windows.WAIT_TIMEOUT) {
					t.Fatal("negative control did not reproduce the orphan window", state)
				}
			} else if state != windows.WAIT_OBJECT_0 {
				state, err = windows.WaitForSingleObject(child, 4500)
				if err != nil || state != windows.WAIT_OBJECT_0 {
					t.Fatal("atomically contained child survived host death", state, err)
				}
			}
			t.Logf("CHILD_CREATE_WINDOW mode=%s pid=%d parent_dead=true child_wait=%d", mode, pid, state)
		})
	}
}

func TestHostedFullOutputPipesDoNotBlockTermination(t *testing.T) {
	p := startFixture(t, true, "flood")
	if err := p.Resume(); err != nil {
		t.Fatal(err)
	}
	peek := windows.NewLazySystemDLL("kernel32.dll").NewProc("PeekNamedPipe")
	available := func(file *winhandle.File) uint32 {
		var n uint32
		ok, _, err := peek.Call(file.Fd(), 0, 0, 0, uintptr(unsafe.Pointer(&n)), 0)
		if ok == 0 {
			t.Fatal("peek child pipe", err)
		}
		return n
	}
	deadline := time.Now().Add(10 * time.Second)
	for available(p.Output) < 4096 || available(p.Errors) < 4096 {
		if time.Now().After(deadline) {
			t.Fatal("child did not fill both independently unread pipes")
		}
		time.Sleep(10 * time.Millisecond)
	}
	started := time.Now()
	if err := p.Terminate(); err != nil {
		t.Fatal(err)
	}
	if exit := awaitExit(t, p); !exit.Forced {
		t.Fatal("unread-pipe fixture was not killed", exit)
	}
	if time.Since(started) > 3*time.Second {
		t.Fatal("output readers delayed process termination")
	}
	t.Logf("CHILD_BACKPRESSURE stdout_unread=true stderr_unread=true exit_ms=%d", time.Since(started).Milliseconds())
}

func TestEnvironmentIsExplicitAndBounded(t *testing.T) {
	for _, env := range [][]string{nil, {"A=bad\x00value"}, {"A=" + strings.Repeat("x", 32767)}} {
		if _, err := environment(env); err == nil {
			t.Fatal("invalid environment accepted")
		}
	}
	for _, env := range [][]string{{}, {"A=value", "=C:=C:\\", "SystemRoot=C:\\Windows"}} {
		block, err := environment(env)
		if err != nil || len(block) < 2 || block[len(block)-1] != 0 || block[len(block)-2] != 0 {
			t.Fatal(block, err)
		}
	}
}

func TestRegistrarParentRequiresExplicitGuard(t *testing.T) {
	flags := uint32(windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK | windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS)
	for _, tc := range []struct {
		flags, count, ui uint32
		pass             bool
	}{
		{flags, 1, 0, true}, {flags &^ windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, 1, 0, false},
		{flags &^ windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK, 1, 0, false}, {flags | windows.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK, 1, 0, false},
		{flags, 0, 0, false}, {flags, 1, windows.JOB_OBJECT_UILIMIT_HANDLES, false},
	} {
		err := checkRegistrarLimits(windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{LimitFlags: tc.flags, ActiveProcessLimit: tc.count}, tc.ui)
		if (err == nil) != tc.pass {
			t.Fatal(tc, err)
		}
	}
}

func startFixture(t *testing.T, registrar bool, args ...string) *Process {
	t.Helper()
	if !hosted() {
		t.Skip("guarded process proofs run only on hosted runners")
	}
	p, err := StartSelf(Options{Args: append([]string{"--guarded-child-fixture"}, args...), Env: os.Environ(), RegistrarBreakaway: registrar})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})
	if p.Identity.PID == 0 || p.Identity.Created == 0 || p.Identity.Image == "" {
		t.Fatal("missing verified identity", p.Identity)
	}
	return p
}

func awaitExit(t *testing.T, p *Process) Exit {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	exit, err := p.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return exit
}

func TestHostedAtomicLaunchAndRawExit(t *testing.T) {
	for _, code := range []uint32{0, 3, 7, 0xc0000005} {
		p := startFixture(t, false, "exit", fmt.Sprint(code))
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		_, err := p.Wait(ctx)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("suspended child executed", err)
		}
		if ok, err := p.Contains(p.process.Handle("test child membership")); err != nil || !ok {
			t.Fatal(ok, err)
		}
		if err := p.Resume(); err != nil {
			t.Fatal(err)
		}
		exit := awaitExit(t, p)
		if exit.Code != code || exit.Forced {
			t.Fatal("raw exit changed", code, exit)
		}
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
		t.Logf("CHILD_EXIT pid=%d created=%d code=%#x forced=%t", p.Identity.PID, p.Identity.Created, exit.Code, exit.Forced)
	}
}

func TestHostedGuardPolicyAndForcedSuspendedExit(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		p := startFixture(t, allowed, "parent")
		if err := p.Resume(); err != nil {
			t.Fatal(err)
		}
		line, err := bufio.NewReader(p.Output).ReadString('\n')
		if err != nil || strings.TrimSpace(line) != strconv.FormatBool(allowed) {
			t.Fatal("unexpected registrar permission", line, err)
		}
		if exit := awaitExit(t, p); exit.Code != 0 || exit.Forced {
			t.Fatal(exit)
		}
	}
	p := startFixture(t, true, "hold")
	if err := p.Terminate(); err != nil {
		t.Fatal(err)
	}
	if exit := awaitExit(t, p); !exit.Forced || exit.Code == 0 || exit.Code == 3 {
		t.Fatal("suspended kill became clean", exit)
	}
}

func TestHostedCloseFailurePreservesRawExit(t *testing.T) {
	p := startFixture(t, true, "exit", "3")
	if err := p.Resume(); err != nil {
		t.Fatal(err)
	}
	want := awaitExit(t, p)
	original := closeOwner
	defer func() { closeOwner = original; p.closeErr = nil }() // injected result only
	failure := errors.New("injected post-close result")
	closeOwner = func(owner winhandle.Owner, site string) error {
		err := original(owner, site)
		if site == "guarded child process close" {
			return errors.Join(err, failure)
		}
		return err
	}
	if err := p.Close(); !errors.Is(err, failure) {
		t.Fatal("close failure lost", err)
	}
	if got := awaitExit(t, p); got != want || got.Code != 3 || got.Forced {
		t.Fatal("cleanup rewrote child outcome", got, want)
	}
	if err := p.Close(); !errors.Is(err, failure) {
		t.Fatal("repeat close lost failure", err)
	}
}
