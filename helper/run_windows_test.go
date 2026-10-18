package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestHiddenCommandHasNoWindow(t *testing.T) {
	cmd := hiddenCommand(`C:\Program Files\Net Switch\runtime\node.exe`, []string{"server.mjs"})
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.HideWindow {
		t.Fatal("the program's window is not hidden")
	}
	if cmd.SysProcAttr.CreationFlags&windows.CREATE_NO_WINDOW == 0 {
		t.Fatal("the program gets a console window")
	}
	// Nothing reads a background server's console: no handles of ours leak to it.
	if cmd.Stdin != nil || cmd.Stdout != nil || cmd.Stderr != nil {
		t.Fatal("the program's standard input or output is connected")
	}
}

func TestRunNeedsAFullPath(t *testing.T) {
	if code := runHidden("node.exe", nil); code != 2 {
		t.Fatalf("a bare program name gave exit code %d, want 2", code)
	}
}

// The helper passes the program's exit code on, so the Task Scheduler shows
// how the server ended. Runs this test binary itself as the program.
func TestRunPassesTheExitCodeOn(t *testing.T) {
	if os.Getenv("NETSWITCH_RUN_CHILD") == "1" {
		os.Exit(7)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// The job ends this test binary's children with it, so run the check in a
	// child test process of its own rather than in this one.
	cmd := exec.Command(self, "-test.run=TestRunInChild")
	cmd.Env = append(os.Environ(), "NETSWITCH_RUN_PARENT=1")
	output, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "PASS") {
		t.Fatalf("child check failed: %v\n%s", err, output)
	}
}

func TestRunInChild(t *testing.T) {
	if os.Getenv("NETSWITCH_RUN_PARENT") != "1" {
		t.Skip("runs only as the child of TestRunPassesTheExitCodeOn")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	os.Setenv("NETSWITCH_RUN_CHILD", "1")
	defer os.Unsetenv("NETSWITCH_RUN_CHILD")
	if code := runHidden(self, []string{"-test.run=TestRunPassesTheExitCodeOn"}); code != 7 {
		t.Fatalf("exit code %d, want 7", code)
	}
}
