//go:build windows

package wintun

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// These two proofs close gaps the earlier registrar tests leave open. Both run
// a REAL device registration (not a synthetic or device-less fixture) and lose
// it through a documented trigger, then witness the outcome from native state
// the registrar never reports about itself.
//
//   - TestWintunRegistrarSurpriseRemovalReleasesCrossProcessRegistration drives
//     the documented SwDeviceClose surprise-removal path (WintunCloseAdapter in
//     the adapter's creator) against a live registration held in a SEPARATE
//     registrar process, and proves the session reports removal (not owner
//     death) while the registrar survives the driver's cross-process handle
//     force-close and then exits cleanly on its own stop request.
//   - TestWintunRegistrarEngineCrashReleasesRealRegistration crashes the engine
//     process that holds a real, traffic-carrying registration and proves the
//     registrar is reaped, the driver releases the registration, and a fresh
//     production session re-registers and carries packets on the SAME adapter,
//     which a surviving creator keeps present so the recovery is attributable
//     to release, not to the adapter vanishing.
//
// Both are hosted-only (requireRunner). They avoid the device-file guard on
// purpose: these tests do not assert the engine holds no device file (the
// registrar design already proves that elsewhere), and the guard's baseline is
// under separate repair. Unrelated-handle survival is witnessed inline instead.

// ---- child modes, selected by their own -test.run in a subprocess ----

// surpriseCreatorChild creates the adapter (so its SwDevice lifetime handle
// lives here), reports the instance, waits for a one-line command on stdin, and
// then closes the adapter. WintunCloseAdapter calls SwDeviceClose, which PnP
// turns into an asynchronous surprise removal of the started device; the signed
// DLL then also issues DIF_REMOVE. The process exits once close returns.
func TestWintunRegistrarSurpriseCreatorChild(t *testing.T) {
	guid := os.Getenv("NETSWITCH_WINTUN_SURPRISE_CREATOR")
	if guid == "" {
		t.Skip("surprise-removal creator child only")
	}
	requireRunner(t)
	a, err := Create(Config{Name: "NsRingSurpriseCI", GUID: guid, Capacity: MinCapacity})
	must(t, err)
	fmt.Println("CREATOR_READY " + a.InstanceID())
	var line [16]byte
	if _, err := os.Stdin.Read(line[:]); err != nil { // the parent's close command, or its exit
		a.Close()
		t.Fatalf("creator child lost its command pipe: %v", err)
	}
	must(t, a.Close()) // SwDeviceClose -> surprise removal, then DIF_REMOVE
	fmt.Println("CREATOR_CLOSED")
}

// realEngineHolderChild stands in for the engine: it opens the adapter the
// parent created and configured, starts a production registrar session, proves
// the registration is real by carrying packets, then reports the registrar PID
// and blocks. It never retires anything; the parent crashes this process.
func TestWintunRegistrarRealEngineHolderChild(t *testing.T) {
	guid := os.Getenv("NETSWITCH_WINTUN_REAL_ENGINE_HOLDER")
	if guid == "" {
		t.Skip("real engine holder child only")
	}
	requireRunner(t)
	a, err := Open(Config{Name: "NsRingCI", GUID: guid, Capacity: MinCapacity})
	must(t, err)
	f := fixtureOnAdapter(t, "ours", a) // real production registrar + echo + link warm-up
	exchange(t, 16)                     // a real, traffic-carrying registration before the crash
	if f.faults.Load() != 0 {
		t.Fatalf("engine holder session failed before reporting ready: %v", f.fault())
	}
	s := f.io.(*Session)
	fmt.Printf("HOLDER_READY %d\n", s.Stats().Registrar.PID)
	for {
		time.Sleep(time.Hour)
	}
}

// ---- shared helpers ----

// pinProcess opens a stable, synchronize-able handle to pid so a later exit
// check cannot be fooled by PID recycling.
func pinProcess(t *testing.T, pid uint32) windows.Handle {
	t.Helper()
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	must(t, err)
	return h
}

// startSessionEventually re-registers, tolerating only the documented transient
// STATUS_ALREADY_INITIALIZED the 0.14.1 driver returns while removal still owns
// RegistrationLock (the same condition reopenRings retries). Any other failure
// is fatal, so a real inability to re-register is never masked.
func startSessionEventually(t *testing.T, a *Adapter, within time.Duration) *Session {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		s, err := a.StartSession()
		if err == nil {
			return s
		}
		if !errors.Is(err, windows.ERROR_ALREADY_INITIALIZED) || time.Now().After(deadline) {
			must(t, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type survivingHandle struct{ h, witness windows.Handle }

// unrelatedHandles returns engine-owned events plus identity witnesses, so a
// loss that wrongly closes or reuses an unrelated handle is detectable.
func unrelatedHandles(t *testing.T, n int) []survivingHandle {
	t.Helper()
	var guards []survivingHandle
	for range n {
		h := testEvent(t)
		guards = append(guards, survivingHandle{h, witness(t, h)})
	}
	t.Cleanup(func() {
		for _, g := range guards {
			if sameObject(g.h, g.witness) {
				windows.CloseHandle(g.h)
			}
			windows.CloseHandle(g.witness)
		}
	})
	return guards
}

func assertUnrelatedHandlesSurvive(t *testing.T, guards []survivingHandle) {
	t.Helper()
	for i, g := range guards {
		if !sameObject(g.h, g.witness) || windows.SetEvent(g.h) != nil {
			t.Fatalf("the loss closed or replaced unrelated engine handle %d", i)
		}
	}
}

// ---- proof A: documented surprise removal of a live cross-process registration ----

// A child process creates the adapter, so the SwDevice lifetime handle is its
// own. This process opens the same adapter and holds the live registration in a
// separate registrar. When the child closes the adapter, WintunCloseAdapter's
// SwDeviceClose makes PnP surprise-remove the started device; the 0.14.1 driver
// then force-closes our registrar's registering handle by value in the
// registrar process (ObCloseHandle(UserMode)) and publishes both ring release
// markers. The registration owner never touches that value again, so the
// force-close is harmless: a parked reader wakes to ErrAdapterRemoved WITHOUT
// the owner-exit identity (the registrar did not die), and the registrar then
// exits with code 0 on our own stop request, never force-killed.
func TestWintunRegistrarSurpriseRemovalReleasesCrossProcessRegistration(t *testing.T) {
	requireRunner(t)
	guid, err := windows.GenerateGUID()
	must(t, err)
	exe, err := os.Executable()
	must(t, err)
	child := exec.Command(exe, "-test.run=^TestWintunRegistrarSurpriseCreatorChild$", "-test.v")
	child.Env = append(os.Environ(), "NETSWITCH_WINTUN_SURPRISE_CREATOR="+guid.String())
	stdin, err := child.StdinPipe()
	must(t, err)
	instance := readyLine(t, child, "CREATOR_READY ") // registers Kill+Wait cleanup

	borrowed, err := Open(Config{Name: "NsRingSurpriseCI", GUID: guid.String(), Capacity: MinCapacity})
	must(t, err)
	defer borrowed.Close()
	s, err := borrowed.StartSession()
	must(t, err)
	defer s.Close()

	regPID := s.Stats().Registrar.PID
	if regPID == 0 {
		t.Fatal("session reported no registrar")
	}
	registrar := pinProcess(t, regPID)
	defer windows.CloseHandle(registrar)
	if exited, _ := exitState(registrar, 0); exited {
		t.Fatal("registrar exited before the surprise removal")
	}

	// A reader with no traffic must be woken by the loss alone.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	readerErr := make(chan error, 1)
	waits := s.Stats().ReadWaits
	go func() {
		buf := make([]byte, MaxPacketSize)
		for {
			if _, err := s.ReadPacket(ctx, buf); err != nil {
				readerErr <- err
				return
			}
		}
	}()
	for s.Stats().ReadWaits == waits {
		if ctx.Err() != nil {
			t.Fatal("reader never parked")
		}
		time.Sleep(time.Millisecond)
	}
	guards := unrelatedHandles(t, 32)

	started := ticks()
	if _, err := stdin.Write([]byte("close\n")); err != nil {
		t.Fatalf("could not command the creator to close: %v", err)
	}

	select {
	case err = <-readerErr:
	case <-time.After(15 * time.Second):
		t.Fatal("the surprise removal left the reader parked")
	}
	woke := elapsed(started)
	assertLoss(t, "parked reader after surprise removal", err, false)
	assertUnrelatedHandlesSurvive(t, guards)

	// A removed (not owner-exited) session: both directions settle to removal.
	assertLoss(t, "WriteBatch after surprise removal", lossWriteError(t, s), false)
	must(t, s.Close())
	exited, code := exitState(registrar, time.Second)
	if !exited || code != 0 {
		t.Fatalf("registrar did not exit cleanly on its stop after the surprise removal: exited=%v code=%#x", exited, code)
	}
	if st := s.Stats(); st.Recoveries != 0 || st.RecoveryFailures != 0 {
		t.Fatalf("a surprise removal counted as recovery: %+v", st)
	}
	must(t, borrowed.Close())
	assertPnPAbsent(t, instance)
	report(t, map[string]any{"test": "registrar_surprise_removal_cross_process", "arch": runtime.GOARCH,
		"registrar_pid": regPID, "reader_wake_ms": float64(woke) / float64(time.Millisecond),
		"registrar_exit_code": code, "guards_preserved": len(guards), "adapter_removed": true})
}

// ---- proof B: engine crash with a real, traffic-carrying registration ----

// This process creates and configures the adapter and keeps it (its SwDevice
// lifetime handle), so the device survives an engine crash. A child process
// stands in for the engine: it opens the adapter, starts a production registrar
// session, carries real packets, and holds it. Crashing that child reaps its
// registrar (through kill-on-close and the closed control pipe), and the driver
// releases the registration on the registrar's process exit
// (TunProcessNotification -> force unregister -> both markers). Because this
// process still owns the present adapter, a fresh production session that then
// re-registers and carries traffic proves the registration was released, not
// that the adapter disappeared.
func TestWintunRegistrarEngineCrashReleasesRealRegistration(t *testing.T) {
	a := newAdapter(t, MinCapacity) // Create + IP config; requireRunner inside; t.Cleanup a.Close
	instance := a.InstanceID()
	exe, err := os.Executable()
	must(t, err)
	engine := exec.Command(exe, "-test.run=^TestWintunRegistrarRealEngineHolderChild$", "-test.v")
	engine.Env = append(os.Environ(), "NETSWITCH_WINTUN_REAL_ENGINE_HOLDER="+a.config.GUID)
	regPID, err := strconv.ParseUint(readyLine(t, engine, "HOLDER_READY "), 10, 32)
	must(t, err)
	enginePID := uint32(engine.Process.Pid)

	// Pin the registrar before the crash so its exit cannot be mistaken for a
	// recycled PID, and confirm it is the crashing engine's own child.
	registrar := pinProcess(t, uint32(regPID))
	defer windows.CloseHandle(registrar)
	if exited, _ := exitState(registrar, 0); exited {
		t.Fatal("registrar exited before the engine crash")
	}
	entries := processEntries(t, func(e *windows.ProcessEntry32) bool { return e.ProcessID == uint32(regPID) })
	if len(entries) != 1 || entries[0].ParentProcessID != enginePID {
		t.Fatalf("registrar %d is not a child of the holder engine %d: %+v", regPID, enginePID, entries)
	}
	if !pnpExists(t, instance) {
		t.Fatal("the adapter was absent before the engine crash")
	}

	started := ticks()
	must(t, engine.Process.Kill())
	exited, code := exitState(registrar, 10*time.Second)
	if !exited {
		t.Fatal("the registrar outlived the crashed engine; its real registration was not reaped")
	}
	reaped := elapsed(started)
	// The adapter must still be present: this process owns it, so the recovery
	// below is attributable to the driver releasing the registration.
	if !pnpExists(t, instance) {
		t.Fatal("the adapter disappeared with the crashed engine; release cannot be distinguished from removal")
	}

	s := startSessionEventually(t, a, 5*time.Second) // re-registration proves release
	must(t, s.Close())
	f := fixtureOnAdapter(t, "ours", a)
	exchange(t, 16)
	f.stopEcho()
	if f.faults.Load() != 0 {
		t.Fatalf("the re-registered production session failed: %v", f.fault())
	}
	report(t, map[string]any{"test": "registrar_engine_crash_real_registration", "arch": runtime.GOARCH,
		"registrar_pid": regPID, "engine_pid": enginePID, "registrar_exit_code": code,
		"registrar_reaped_after_crash_ms": float64(reaped) / float64(time.Millisecond),
		"adapter_present_after_crash":     true, "reregistered": true})
}
