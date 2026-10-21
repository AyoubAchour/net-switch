//go:build windows

package wintun

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

const handleFlagProtectFromClose = 0x00000002

var compareObjectHandles = windows.NewLazySystemDLL("kernelbase.dll").NewProc("CompareObjectHandles")

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
// either ring marker. This injects that close, plus another owner receiving
// the same number, after closeWith has checked the markers and before its
// own native close.
func TestRingRemovalBetweenMarkerCheckAndClose(t *testing.T) {
	for _, tracked := range []bool{false, true} {
		t.Run(fmt.Sprintf("tracked_replacement=%v", tracked), func(t *testing.T) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			r, err := allocateRings(MinCapacity)
			must(t, err)
			allocation := r.allocation
			defer windows.VirtualFree(allocation, 0, windows.MEM_RELEASE)
			device := testEvent(t)
			deviceWitness := witness(t, device)
			defer windows.CloseHandle(deviceWitness)
			r.device, r.registered = device, true
			r.deviceOwner = winhandle.OpenDriverHandle(device, "test Wintun device")
			var replacement windows.Handle
			var replacementOwner winhandle.Owner
			var driverErr error
			attempts := 0
			inject := func(h windows.Handle) error {
				if h == device {
					driverErr = windows.CloseHandle(h) // TunDispatchPnp's ObCloseHandle(UserMode).
					if driverErr == nil {
						replacement, attempts = reuseValue(t, h)
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
			// No driver exists here and neither marker is published. closeWith
			// retains these pages; the fixture owns their deferred release.
			report(t, map[string]any{"test": "removal_between_marker_check_and_close", "arch": runtime.GOARCH,
				"tracked": tracked, "handlecheck": winhandle.Enabled, "driver_close_error": errText(driverErr),
				"reuse_attempts": attempts, "replacement": replacement != 0, "violation": fmt.Sprint(violation), "close_error": errText(err)})
			if violation != nil {
				if replacement != 0 {
					windows.CloseHandle(replacement)
				}
				if !strings.Contains(fmt.Sprint(violation), "WINDOWS HANDLE OWNERSHIP VIOLATION") {
					panic(violation)
				}
				t.Fatalf("tripwire stopped closing a replaced device number: %v", violation)
			}
			if replacement == 0 && driverErr == nil {
				t.Fatal("the injected removal never had its handle number reused; the race was not exercised")
			}
			if replacement != 0 {
				if err := windows.SetEvent(replacement); err != nil {
					t.Fatalf("closed another owner's handle that reused the device number: %v", err)
				}
				if tracked {
					must(t, replacementOwner.HandleClose("test replacement close"))
				} else {
					must(t, windows.CloseHandle(replacement))
				}
			}
			if sameObject(device, deviceWitness) {
				t.Fatal("the device handle was never closed")
			}
		})
	}
}
