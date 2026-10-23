//go:build windows

package wintun

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"testing"

	"golang.org/x/sys/windows"
)

// Child modes of the same test binary. registrarFixtureMode exercises the real
// registration validation, reply and lifecycle, driven by the
// NETSWITCH_WINTUN_FIXTURE_FAULT environment variable the parent sets through
// the registrarExtraEnv seam. registrarCrasherMode spawns a registrar and then
// "crashes" before resuming it, to prove atomic job membership.
const (
	registrarFixtureMode = "__netswitch-wintun-registrar-fixture"
	registrarCrasherMode = "__netswitch-wintun-registrar-crasher"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 2 {
		switch os.Args[1] {
		case RegistrarMode:
			os.Exit(RunRegistrar())
		case registrarFixtureMode:
			os.Exit(runRegistrarFixture())
		case registrarCrasherMode:
			os.Exit(runRegistrarCrasher())
		}
	}
	if code, handled := runDeviceGuardFixture(m); handled {
		os.Exit(code)
	}
	os.Exit(m.Run())
}

// runRegistrarFixture mirrors the production registrar (prepareRegistration,
// the reply and the EOF wait) but injects the fault named by the environment.
// Only post-register-exit registers a real device and requires an adapter.
func runRegistrarFixture() int {
	stdin, stdout, err := registrarStdHandles()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	fault := os.Getenv("NETSWITCH_WINTUN_FIXTURE_FAULT")
	fail := func(stage string, err error) int {
		sendRegistrarReply(stdout, registrarReply{PID: windows.GetCurrentProcessId(), Stage: stage, Error: err.Error()})
		return 1
	}
	line, err := readLine(stdin, registrarMessageLimit)
	if err != nil {
		return fail("configuration", err)
	}
	var config registrarConfig
	if err := json.Unmarshal(line, &config); err != nil {
		return fail("configuration", err)
	}
	view, desc, memoryType, stage, err := prepareRegistration(config)
	if err != nil {
		return fail(stage, err)
	}
	switch fault {
	case "pre-reply-exit":
		os.Exit(5) // validated and mapped, dies before replying
	case "hang":
		blockForever() // never reply: drives the parent's start timeout
	case "post-register-exit":
		// Actually register the real device (this fault runs with an adapter), so
		// the parent's failure cleanup is proven against a live registration.
		if err := registerDevice(config.Path, &desc); err != nil {
			return fail("register", err)
		}
		os.Exit(6)
	}
	pid := windows.GetCurrentProcessId()
	if fault == "wrong-pid" {
		pid++
	}
	handles, private, measured := registrarUsage()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	sendRegistrarReply(stdout, registrarReply{PID: pid, Ready: true, Address: uint64(view), MemoryType: memoryType,
		FootprintMeasured: measured, Handles: handles, PrivateBytes: private, HeapBytes: stats.HeapAlloc, StackBytes: stats.StackInuse})
	if fault == "block" {
		blockForever() // ignore the control pipe entirely: only kill-on-close can reap this
	}
	return registrarWaitForStop(stdin)
}

// blockForever blocks the thread in a native wait that never completes while
// the process lives, so (unlike select{}) Go's deadlock detector cannot abort
// the fixture and only external termination ends it.
func blockForever() {
	windows.WaitForSingleObject(windows.CurrentProcess(), windows.INFINITE)
	os.Exit(1) // unreachable while the process is alive
}

// runRegistrarCrasher creates a registrar through the production launcher, then
// exits from the before-resume hook without resuming it or closing its handles,
// exactly like a parent crash in the create-to-resume window. The grandchild is
// suspended and in the kill-on-close job, so it must die with this process.
func runRegistrarCrasher() int {
	requireHandshakePipe := func() (stdout windows.Handle) {
		h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
		must := err == nil && isPipe(h)
		if !must {
			fmt.Fprintln(os.Stderr, "crasher requires an inherited stdout pipe")
			os.Exit(2)
		}
		return h
	}
	stdout := requireHandshakePipe()
	r, err := allocateRings(MinCapacity)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := r.createEvents(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	registrarCommand = registrarFixtureMode
	registrarExtraEnv = []string{"NETSWITCH_WINTUN_FIXTURE_FAULT=block"}
	registrarBeforeResume = func(pid uint32, _ windows.Handle) {
		var written uint32
		message := []byte(fmt.Sprintf("GRANDCHILD %d\n", pid))
		windows.WriteFile(stdout, message, &written, nil)
		// Block until the parent has pinned the grandchild PID, then exit without
		// resuming: process teardown closes the only job handle.
		var chunk [8]byte
		var n uint32
		windows.ReadFile(windows.Handle(os.Stdin.Fd()), chunk[:], &n, nil)
		os.Exit(7)
	}
	// This call never returns: the hook exits the process.
	_, _ = startRegistrar(`\\?\SWD#Wintun#{00000000-0000-0000-0000-000000000000}#{cac88484-7515-4c03-82e6-71a87aba61c3}`, r)
	return 0
}
