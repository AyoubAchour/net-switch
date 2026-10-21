//go:build windows

package wintun

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

const handleFlagProtectFromClose = 0x00000002

var compareObjectHandles = windows.NewLazySystemDLL("kernelbase.dll").NewProc("CompareObjectHandles")

var (
	getCurrentProcessorNumber = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetCurrentProcessorNumber")
	setThreadAffinityMask     = windows.NewLazySystemDLL("kernel32.dll").NewProc("SetThreadAffinityMask")
)

// pinToCurrentProcessor keeps this locked OS thread on the processor it is
// running on, and returns a function that restores its previous affinity.
// A freed handle value goes back to a free list that Windows keeps per
// processor, so a thread that migrates between the close and the next
// allocation may never be offered that value again. ARM64 run 39559181981
// showed exactly that: 4,096 allocations without the freed value.
func pinToCurrentProcessor(t *testing.T) (processor uint32, restore func()) {
	t.Helper()
	n, _, _ := getCurrentProcessorNumber.Call()
	if n >= 64 {
		t.Fatalf("processor %d is outside this thread's affinity group mask", n)
	}
	previous, _, err := setThreadAffinityMask.Call(uintptr(windows.CurrentThread()), uintptr(1)<<n)
	if previous == 0 {
		t.Fatalf("pin the test thread to processor %d: %v", n, err)
	}
	return uint32(n), func() {
		if ok, _, err := setThreadAffinityMask.Call(uintptr(windows.CurrentThread()), previous); ok == 0 {
			t.Errorf("restore the test thread's affinity: %v", err)
		}
	}
}

// sameObject reports whether value still names the kernel object behind
// witness. A closed value, or one reused for another object, reports false.
func sameObject(value, witness windows.Handle) bool {
	same, _, _ := compareObjectHandles.Call(uintptr(value), uintptr(witness))
	return same != 0
}

func testEvent(t *testing.T) windows.Handle {
	t.Helper()
	h, err := windows.CreateEvent(nil, 1, 0, nil)
	must(t, err)
	return h
}

func witness(t *testing.T, h windows.Handle) windows.Handle {
	t.Helper()
	var w windows.Handle
	must(t, windows.DuplicateHandle(windows.CurrentProcess(), h, windows.CurrentProcess(), &w, 0, false, windows.DUPLICATE_SAME_ACCESS))
	return w
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	var errno windows.Errno
	if errors.As(err, &errno) {
		return fmt.Sprintf("%d %v", uint32(errno), err)
	}
	return err.Error()
}

// reuseValue allocates events until Windows hands out want again, as another
// goroutine in this process could. It returns 0 if the value never returns.
func reuseValue(t *testing.T, want windows.Handle) (windows.Handle, int) {
	t.Helper()
	var others []windows.Handle
	defer func() {
		for _, h := range others {
			windows.CloseHandle(h)
		}
	}()
	for attempt := 1; attempt <= 4096; attempt++ {
		h := testEvent(t)
		if h == want {
			return h, attempt
		}
		others = append(others, h)
	}
	return 0, 4096
}

// The driver closes registered handles with ObCloseHandle(value, UserMode),
// which applies the same protection rule as a user-mode CloseHandle. This
// probe measures that rule and DuplicateHandle's documented close-source form
// on both runner architectures before any design relies on either.
func TestRingHandleProtectionProbe(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	result := map[string]any{"test": "handle_protection_probe", "arch": runtime.GOARCH}

	protected := testEvent(t)
	keep := witness(t, protected)
	defer windows.CloseHandle(keep)
	must(t, windows.SetHandleInformation(protected, handleFlagProtectFromClose, handleFlagProtectFromClose))
	err := windows.CloseHandle(protected)
	result["protected_close_error"] = errText(err)
	result["protected_close_survived"] = sameObject(protected, keep)
	if err == nil || !sameObject(protected, keep) {
		report(t, result)
		t.Fatal("CloseHandle closed a protected handle")
	}

	err = windows.DuplicateHandle(windows.CurrentProcess(), protected, 0, nil, 0, false, windows.DUPLICATE_CLOSE_SOURCE)
	closed := !sameObject(protected, keep)
	result["protected_close_source_error"] = errText(err)
	result["protected_close_source_closed"] = closed
	if !closed {
		must(t, windows.SetHandleInformation(protected, handleFlagProtectFromClose, 0))
		must(t, windows.CloseHandle(protected))
	}

	plain := testEvent(t)
	plainKeep := witness(t, plain)
	defer windows.CloseHandle(plainKeep)
	err = windows.DuplicateHandle(windows.CurrentProcess(), plain, 0, nil, 0, false, windows.DUPLICATE_CLOSE_SOURCE)
	result["unprotected_close_source_error"] = errText(err)
	result["unprotected_close_source_closed"] = !sameObject(plain, plainKeep)

	same := 0
	const trials = 200
	for range trials {
		h := testEvent(t)
		must(t, windows.CloseHandle(h))
		next := testEvent(t)
		if next == h {
			same++
		}
		must(t, windows.CloseHandle(next))
	}
	result["same_thread_immediate_reuse"] = fmt.Sprintf("%d/%d", same, trials)
	report(t, result)
	if !result["unprotected_close_source_closed"].(bool) {
		t.Fatal("DuplicateHandle close-source did not close an unprotected handle")
	}
}

// Wintun 0.14.1 PnP removal closes the registered handle before it writes
// either ring marker. The legacy subtests are the negative control: they
// inject that close, plus another owner receiving the same number, after the
// former in-process close checked the markers and before its native close, and
// require the race to damage (or the tripwire to stop) the witnessed
// replacement. The production subtests apply the same injection to the
// registrar teardown, which must close only objects it owns.
func TestRingRemovalBetweenMarkerCheckAndClose(t *testing.T) {
	for _, tracked := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy_in_process/tracked_replacement=%v", tracked), func(t *testing.T) {
			// The old close intentionally destroys another owner's object. Its
			// tracking record must remain live to expose that defect; resetting
			// the registry would conceal it. Give each negative control its own
			// process so the deliberate corruption cannot poison later tests.
			if os.Getenv("NETSWITCH_WINTUN_LEGACY_CLOSE_CHILD") == "1" {
				legacyCloseWindow(t, tracked)
				return
			}
			exe, err := os.Executable()
			must(t, err)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			pattern := fmt.Sprintf("^TestRingRemovalBetweenMarkerCheckAndClose$/^legacy_in_process$/^tracked_replacement=%v$", tracked)
			cmd := exec.CommandContext(ctx, exe, "-test.v", "-test.run="+pattern)
			cmd.Env = append(os.Environ(), "NETSWITCH_WINTUN_LEGACY_CLOSE_CHILD=1")
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			output, err := cmd.CombinedOutput()
			t.Logf("isolated legacy negative control:\n%s", output)
			if err != nil || !strings.Contains(string(output), `"owner":"legacy_in_process"`) || !strings.Contains(string(output), "--- PASS: TestRingRemovalBetweenMarkerCheckAndClose/legacy_in_process/tracked_replacement=") {
				t.Fatalf("legacy negative control did not complete its witness assertions: %v", err)
			}
		})
	}
	for _, markers := range []string{"before", "during", "missing"} {
		t.Run("production_registrar/markers="+markers, func(t *testing.T) {
			productionCloseWindow(t, markers)
		})
	}
}

func legacyCloseWindow(t *testing.T, tracked bool) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	processor, restore := pinToCurrentProcessor(t)
	defer restore()
	r, err := allocateRings(MinCapacity)
	must(t, err)
	view := r.view
	// No driver exists and no marker is published: the legacy close retains
	// this view. The fixture owns its deferred release.
	defer windows.UnmapViewOfFile(view)
	device := testEvent(t)
	deviceWitness := witness(t, device)
	defer windows.CloseHandle(deviceWitness)
	r.owner = &inProcessOwner{device: device, registered: true,
		deviceOwner: winhandle.OpenDriverHandle(device, "test Wintun device")}
	var replacement windows.Handle
	var replacementWitness windows.Handle
	defer func() {
		if replacementWitness != 0 {
			windows.CloseHandle(replacementWitness)
		}
	}()
	var replacementOwner winhandle.Owner
	var driverErr error
	attempts := 0
	inject := func(h windows.Handle) error {
		if h == device {
			driverErr = windows.CloseHandle(h) // TunDispatchPnp's ObCloseHandle(UserMode).
			if driverErr == nil {
				replacement, attempts = reuseValue(t, h)
				if replacement != 0 {
					replacementWitness = witness(t, replacement)
				}
				if replacement != 0 && tracked {
					replacementOwner = winhandle.Open(replacement, "test replacement owner")
				}
			}
		}
		return windows.CloseHandle(h)
	}
	var violation any
	func() {
		defer func() { violation = recover() }()
		err = r.closeWith(inject)
	}()
	if violation != nil && !r.section.IsZero() {
		// The tripwire stopped closeWith before its memory phase.
		r.section.HandleClose("test section after violation")
	}
	survived := replacement != 0 && sameObject(replacement, replacementWitness)
	tripwire := violation != nil && strings.Contains(fmt.Sprint(violation), "WINDOWS HANDLE OWNERSHIP VIOLATION")
	report(t, map[string]any{"test": "removal_between_marker_check_and_close", "arch": runtime.GOARCH,
		"owner": "legacy_in_process", "tracked": tracked, "handlecheck": winhandle.Enabled, "pinned_processor": processor,
		"driver_close_error": errText(driverErr), "reuse_attempts": attempts, "replacement": replacement != 0,
		"replacement_survived": survived, "tripwire": tripwire, "violation": fmt.Sprint(violation), "close_error": errText(err)})
	if survived {
		if replacementOwner.IsZero() {
			windows.CloseHandle(replacement)
		} else {
			replacementOwner.HandleClose("test replacement close")
		}
	}
	if violation != nil && !tripwire {
		panic(violation)
	}
	if replacement == 0 {
		t.Fatalf("the injected removal never had its handle number reused (driver close: %v); the race was not exercised", driverErr)
	}
	if sameObject(device, deviceWitness) {
		t.Fatal("the device handle was never closed")
	}
	// The control holds only if the legacy ordering really reaches the
	// replacement: it is destroyed, or the handlecheck tripwire stops the close.
	if survived && !tripwire {
		t.Fatal("negative control lost: the legacy check-to-close ordering left the replacement intact")
	}
}

// productionCloseWindow runs the real registrar launcher, job, inheritance,
// validation and teardown against a device-less fixture registrar. Each close
// the teardown performs is checked against a witness of an object the rings
// own, and its number is immediately handed to another owner, as a concurrent
// goroutine could. The driver's removal markers are published before, during
// or never.
func productionCloseWindow(t *testing.T, markers string) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	previous := registrarCommand
	registrarCommand = registrarFixtureMode
	defer func() { registrarCommand = previous }()
	r, err := allocateRings(MinCapacity)
	must(t, err)
	if err := r.createEvents(); err != nil {
		t.Fatal(errors.Join(err, r.close()))
	}
	g, err := startRegistrar(`\\?\SWD#Wintun#{00000000-0000-0000-0000-000000000000}#{cac88484-7515-4c03-82e6-71a87aba61c3}`, r)
	if err != nil {
		t.Fatal(errors.Join(err, r.close()))
	}
	r.owner = g
	owned := map[windows.Handle]windows.Handle{}
	for _, h := range []windows.Handle{r.readHandle(), r.writeHandle(), r.section.Handle("test section witness"),
		g.process.Handle("test process witness"), g.job.Handle("test job witness"), g.control.Handle("test control witness")} {
		owned[h] = witness(t, h)
	}
	total := len(owned)
	process := witness(t, g.process.Handle("test exit witness"))
	defer windows.CloseHandle(process)
	defer func() {
		for _, w := range owned {
			windows.CloseHandle(w)
		}
	}()
	publish := func() {
		r.receive.store(0, ^uint32(0))
		r.send.store(4, ^uint32(0))
	}
	if markers == "before" {
		publish()
	}
	type replaced struct{ value, witness windows.Handle }
	var replacements []replaced
	defer func() {
		for _, p := range replacements {
			if sameObject(p.value, p.witness) {
				windows.CloseHandle(p.value)
			}
			windows.CloseHandle(p.witness)
		}
	}()
	var foreign []windows.Handle
	closes := 0
	inject := func(h windows.Handle) error {
		w, ok := owned[h]
		if !ok || !sameObject(h, w) {
			foreign = append(foreign, h)
			return windows.ERROR_INVALID_HANDLE // refuse: never close another owner's object
		}
		// Done verifying identity: release our witness BEFORE closing the real
		// handle, so closing the control writer actually reaches the helper as
		// EOF (a lingering duplicate writer would hide it) and no witness leaks.
		windows.CloseHandle(w)
		delete(owned, h)
		closes++
		if closes == 1 && markers == "during" {
			publish()
		}
		err := windows.CloseHandle(h)
		if replacement, _ := reuseValue(t, h); replacement != 0 {
			replacements = append(replacements, replaced{replacement, witness(t, replacement)})
		}
		return err
	}
	err = r.closeWith(inject)
	exit, _ := windows.WaitForSingleObject(process, 0)
	var code uint32
	windows.GetExitCodeProcess(process, &code)
	survivors := 0
	for _, p := range replacements {
		if sameObject(p.value, p.witness) && windows.SetEvent(p.value) == nil {
			survivors++
		}
	}
	report(t, map[string]any{"test": "removal_between_marker_check_and_close", "arch": runtime.GOARCH,
		"owner": "production_registrar", "markers": markers, "handlecheck": winhandle.Enabled,
		"owned": total, "closes": closes, "foreign_closes": len(foreign), "replacements": len(replacements),
		"replacements_survived": survivors, "registrar_exited": exit == windows.WAIT_OBJECT_0, "registrar_exit_code": code,
		"close_error": errText(err)})
	if len(foreign) != 0 {
		t.Fatalf("teardown tried to close %d values it did not own: %v", len(foreign), foreign)
	}
	if closes != total {
		t.Fatalf("teardown closed %d of its %d owned objects", closes, total)
	}
	if len(replacements) == 0 {
		t.Fatal("no closed number was reused; the race was not exercised")
	}
	if survivors != len(replacements) {
		t.Fatalf("teardown destroyed %d of %d replacement objects", len(replacements)-survivors, len(replacements))
	}
	if exit != windows.WAIT_OBJECT_0 || code != 0 {
		t.Fatalf("fixture registrar did not exit cleanly on its stop request: wait=%d code=%#x", exit, code)
	}
	switch markers {
	case "missing":
		if !errors.Is(err, errRegistrationHeld) || errors.Is(err, errRegistrarAlive) {
			t.Fatalf("missing driver markers were not reported: %v", err)
		}
	default:
		must(t, err)
	}
}
