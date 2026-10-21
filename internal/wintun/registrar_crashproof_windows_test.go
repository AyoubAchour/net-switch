//go:build windows

package wintun

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
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
//   - TestWintunRegistrarEngineCrashReleasesRealRegistration terminates the
//     engine process that holds a real, traffic-carrying registration and
//     proves the registrar is reaped, the driver releases the registration, and
//     one fresh production session re-registers and carries packets on the SAME
//     adapter, which a surviving creator keeps present so the recovery is
//     attributable to release, not to the adapter vanishing.
//
// The engine loss here is an abrupt TerminateProcess, which these tests treat
// only as process death; they make no claim about Go's unhandled-exception
// behaviour. Both are hosted-only (requireRunner) and avoid the device-file
// guard on purpose: they do not assert the engine holds no device file (proven
// elsewhere), and the guard's baseline is under separate repair. Unrelated
// handle survival is witnessed inline instead.

// ---- child modes, selected by their own -test.run in a subprocess ----

// surpriseCreatorChild creates the adapter (so its SwDevice lifetime handle
// lives here), reports the instance, waits for the exact "close" command on
// stdin, and then closes the adapter. WintunCloseAdapter calls SwDeviceClose,
// which PnP turns into an asynchronous surprise removal of the started device;
// the signed DLL then also issues DIF_REMOVE. CREATOR_CLOSED is printed only
// after close returns, and the process exits code 0.
func TestWintunRegistrarSurpriseCreatorChild(t *testing.T) {
	guid := os.Getenv("NETSWITCH_WINTUN_SURPRISE_CREATOR")
	if guid == "" {
		t.Skip("surprise-removal creator child only")
	}
	requireRunner(t)
	a, err := Create(Config{Name: "NsRingSurpriseCI", GUID: guid, Capacity: MinCapacity})
	must(t, err)
	fmt.Println("CREATOR_READY " + a.InstanceID())
	command, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil || strings.TrimSpace(command) != "close" {
		a.Close() // on a lost command pipe, still remove the owned device before failing
		t.Fatalf("creator child expected the close command, got %q (err %v)", command, err)
	}
	must(t, a.Close()) // SwDeviceClose -> surprise removal, then DIF_REMOVE
	fmt.Println("CREATOR_CLOSED")
}

// realEngineHolderChild stands in for the engine: it opens the adapter the
// parent created and configured, starts a production registrar session, proves
// the registration is real by carrying packets, then reports the registrar PID
// and blocks. It never retires anything; the parent terminates this process.
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

// ---- completion-aware child process wrapper ----

// managedChild owns a child test process. One goroutine reads its stdout to
// EOF and can never block: only the declared marker lines are offered to a
// bounded channel with a non-blocking send, everything else goes to a bounded
// diagnostic tail, and a duplicate or overflowing marker is a recorded failure
// that kills the child but keeps draining. At EOF the child is reaped with a
// single Wait. No path calls Wait twice, and no unread output can wedge the
// child on a full pipe.
type managedChild struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	lines chan string   // declared markers only
	done  chan struct{} // closed after the single Wait returns
	code  int           // valid once done is closed

	mu   sync.Mutex
	err  error    // first reader failure (duplicate/overflow/scan error)
	tail []string // bounded diagnostic tail of non-marker lines
}

func (c *managedChild) fail(err error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	c.mu.Unlock()
	c.cmd.Process.Kill() // unblock the child; the reader keeps draining to EOF
}

func (c *managedChild) firstErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *managedChild) addTail(line string) {
	c.mu.Lock()
	c.tail = append(c.tail, line)
	if len(c.tail) > 20 {
		c.tail = c.tail[len(c.tail)-20:]
	}
	c.mu.Unlock()
}

func (c *managedChild) diagnostics() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.tail, "\n")
}

func matchMarker(line string, markers []string) (string, bool) {
	for _, m := range markers {
		if strings.HasPrefix(line, m) {
			return m, true
		}
	}
	return "", false
}

// startChild launches exe in the named test mode with one extra environment
// entry. markers are the stdout prefixes await can wait for; afterJoin, if set,
// runs inside the cleanup once the child is killed and reaped, so a creator's
// owned-GUID device is swept and its absence asserted only after it is gone.
func startChild(t *testing.T, mode, env string, markers []string, afterJoin func()) *managedChild {
	t.Helper()
	exe, err := os.Executable()
	must(t, err)
	c := &managedChild{lines: make(chan string, 8), done: make(chan struct{})}
	c.cmd = exec.Command(exe, "-test.run=^"+mode+"$", "-test.v")
	c.cmd.Env = append(os.Environ(), env)
	c.cmd.Stderr = os.Stderr
	c.stdin, err = c.cmd.StdinPipe()
	must(t, err)
	stdout, err := c.cmd.StdoutPipe()
	must(t, err)
	must(t, c.cmd.Start())
	go func() {
		scan := bufio.NewScanner(stdout)
		seen := map[string]bool{}
		for scan.Scan() {
			line := scan.Text()
			prefix, isMarker := matchMarker(line, markers)
			if !isMarker {
				c.addTail(line)
				continue
			}
			if seen[prefix] {
				c.fail(fmt.Errorf("child repeated marker %q", prefix))
				continue
			}
			seen[prefix] = true
			select {
			case c.lines <- line:
			default:
				c.fail(fmt.Errorf("child marker channel overflow at %q", line))
			}
		}
		if err := scan.Err(); err != nil {
			c.fail(fmt.Errorf("child stdout scan: %w", err))
		}
		c.cmd.Wait() // all reads are done: reap exactly once
		c.code = c.cmd.ProcessState.ExitCode()
		close(c.done)
	}()
	t.Cleanup(func() {
		c.stdin.Close()      // EOF for a child blocked reading stdin; all paths
		c.cmd.Process.Kill() // idempotent
		select {
		case <-c.done:
		case <-time.After(10 * time.Second):
			t.Errorf("child %d did not exit during cleanup", c.cmd.Process.Pid)
		}
		if afterJoin != nil {
			afterJoin()
		}
	})
	return c
}

// await returns the text after prefix on the child's first matching line, or
// fails on the child's exit, a recorded reader failure, or the deadline. On
// exit it still drains already buffered markers, so one printed just before
// exit is not missed.
func (c *managedChild) await(t *testing.T, prefix string, within time.Duration) string {
	t.Helper()
	deadline := time.After(within)
	for {
		select {
		case line := <-c.lines:
			if rest, ok := strings.CutPrefix(line, prefix); ok {
				return rest
			}
		case <-c.done:
			for {
				select {
				case line := <-c.lines:
					if rest, ok := strings.CutPrefix(line, prefix); ok {
						return rest
					}
				default:
					if err := c.firstErr(); err != nil {
						t.Fatalf("child failed before reporting %q: %v\n%s", prefix, err, c.diagnostics())
					}
					t.Fatalf("child exited (code %d) before reporting %q\n%s", c.code, prefix, c.diagnostics())
				}
			}
		case <-deadline:
			t.Fatalf("child did not report %q within %v\n%s", prefix, within, c.diagnostics())
		}
	}
}

// join returns the recorded exit code once the child has exited. Wait already
// ran in the reader goroutine; this only observes its result and surfaces any
// reader failure.
func (c *managedChild) join(t *testing.T, within time.Duration) int {
	t.Helper()
	select {
	case <-c.done:
		if err := c.firstErr(); err != nil {
			t.Fatalf("child reader failed: %v\n%s", err, c.diagnostics())
		}
		return c.code
	case <-time.After(within):
		t.Fatalf("child did not exit within %v\n%s", within, c.diagnostics())
		return 0
	}
}

// ---- native witnesses ----

// pinProcess opens a stable, synchronize-able handle to pid so a later exit
// check cannot be fooled by PID recycling.
func pinProcess(t *testing.T, pid uint32) windows.Handle {
	t.Helper()
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	must(t, err)
	return h
}

// devicePresent reports whether the exact Wintun device instance exists. With
// presentOnly it enumerates DIGCF_PRESENT ("is the started device there");
// without it, all records including non-present phantoms. It returns errors
// instead of failing, so cleanup can use it without a fatal.
func devicePresent(instance string, presentOnly bool) (bool, error) {
	flags := uint32(0)
	if presentOnly {
		flags = windows.DIGCF_PRESENT
	}
	set, err := windows.SetupDiGetClassDevsEx(&netClass, "SWD\\Wintun", 0, flags, 0, "")
	if err != nil {
		return false, err
	}
	defer set.Close()
	for i := 0; ; i++ {
		dev, err := set.EnumDeviceInfo(i)
		if err == windows.ERROR_NO_MORE_ITEMS {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		id, err := set.DeviceInstanceID(dev)
		if err != nil {
			return false, err
		}
		if strings.EqualFold(id, instance) {
			return true, nil
		}
	}
}

// pnpPresent is the fatal-on-error body wrapper for a DIGCF_PRESENT exact
// match. Unlike pnpExists it does not match non-present phantom records.
func pnpPresent(t *testing.T, instance string) bool {
	t.Helper()
	present, err := devicePresent(instance, true)
	must(t, err)
	return present
}

type survivingHandle struct{ h, witness windows.Handle }

// unrelatedHandles returns engine-owned events plus identity witnesses, so a
// loss that wrongly closes or reuses an unrelated handle is detectable. The
// cleanup is installed before any allocation, and each handle is recorded with
// a zero witness before its witness is taken, so a Fatal in testEvent or
// witness still frees every handle built so far.
func unrelatedHandles(t *testing.T, n int) []survivingHandle {
	t.Helper()
	var guards []survivingHandle
	t.Cleanup(func() {
		for _, g := range guards {
			if g.witness == 0 {
				windows.CloseHandle(g.h) // owned but not yet witnessed
				continue
			}
			if sameObject(g.h, g.witness) {
				windows.CloseHandle(g.h)
			}
			windows.CloseHandle(g.witness)
		}
	})
	for range n {
		h := testEvent(t)
		guards = append(guards, survivingHandle{h: h})
		guards[len(guards)-1].witness = witness(t, h)
	}
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
	config := Config{Name: "NsRingSurpriseCI", GUID: guid.String(), Capacity: MinCapacity}
	var instance string
	// Cleanup reaps the creator and only then confirms its owned-GUID device is
	// gone: the creator owns the device (Create), so borrowed.Close releases a
	// reference without removing it. This can only fail the proof, never pass it.
	sweepCreatorPhantom := func() {
		if instance != "" {
			deadline := time.Now().Add(5 * time.Second)
			for {
				present, err := devicePresent(instance, true)
				if err != nil {
					t.Errorf("surprise cleanup present check: %v", err)
					break
				}
				if !present {
					break
				}
				if time.Now().After(deadline) {
					t.Errorf("owned adapter %s still present after the creator exited", instance)
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
		if removed, err := recoverAfterCrash(config); err != nil {
			t.Errorf("surprise-removal phantom cleanup failed: removed=%d err=%v", removed, err)
		}
		if instance != "" {
			if present, err := devicePresent(instance, false); err != nil || present {
				t.Errorf("adapter %s left behind after cleanup: present=%v err=%v", instance, present, err)
			}
		}
	}
	creator := startChild(t, "TestWintunRegistrarSurpriseCreatorChild", "NETSWITCH_WINTUN_SURPRISE_CREATOR="+guid.String(),
		[]string{"CREATOR_READY ", "CREATOR_CLOSED"}, sweepCreatorPhantom)
	instance = creator.await(t, "CREATOR_READY ", 30*time.Second)

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
	if !pnpPresent(t, instance) {
		t.Fatal("the adapter was not present before the surprise removal")
	}

	// A reader with no traffic must be woken by the loss alone. It is cancelled
	// and joined on every exit path, including the fatal ones.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	readerErr := make(chan error, 1)
	readerDone := make(chan struct{})
	waits := s.Stats().ReadWaits
	go func() {
		defer close(readerDone)
		buf := make([]byte, MaxPacketSize)
		for {
			if _, err := s.ReadPacket(ctx, buf); err != nil {
				readerErr <- err
				return
			}
		}
	}()
	t.Cleanup(func() { cancel(); <-readerDone })
	for s.Stats().ReadWaits == waits {
		if ctx.Err() != nil {
			t.Fatal("reader never parked")
		}
		time.Sleep(time.Millisecond)
	}
	guards := unrelatedHandles(t, 32)

	started := ticks()
	if _, err := creator.stdin.Write([]byte("close\n")); err != nil {
		t.Fatalf("could not command the creator to close: %v", err)
	}
	creator.stdin.Close() // close the child's control pipe

	select {
	case err = <-readerErr:
	case <-time.After(15 * time.Second):
		t.Fatal("the surprise removal left the reader parked")
	}
	woke := elapsed(started)
	assertLoss(t, "parked reader after surprise removal", err, false)
	assertUnrelatedHandlesSurvive(t, guards)
	assertLoss(t, "WriteBatch after surprise removal", lossWriteError(t, s), false)

	must(t, s.Close())
	regExited, regCode := exitState(registrar, time.Second)
	if !regExited || regCode != 0 {
		t.Fatalf("registrar did not exit cleanly on its stop after the surprise removal: exited=%v code=%#x", regExited, regCode)
	}
	// The reader loss can precede the creator's DIF_REMOVE. Require the creator's
	// own completion marker and a clean exit before closing our reference (which
	// queues the DLL's orphan sweep) and asserting the device is gone.
	creator.await(t, "CREATOR_CLOSED", 20*time.Second)
	creatorCode := creator.join(t, 5*time.Second)
	if creatorCode != 0 {
		t.Fatalf("creator did not close the adapter cleanly: exit code %d", creatorCode)
	}
	if st := s.Stats(); st.Recoveries != 0 || st.RecoveryFailures != 0 {
		t.Fatalf("a surprise removal counted as recovery: %+v", st)
	}
	must(t, borrowed.Close())
	assertPnPAbsent(t, instance)       // no leftover records, phantoms included
	present := pnpPresent(t, instance) // native postcondition, not the test's say-so
	if present {
		t.Fatalf("adapter %s still present after surprise removal", instance)
	}
	report(t, map[string]any{"test": "registrar_surprise_removal_cross_process", "arch": runtime.GOARCH,
		"registrar_pid": regPID, "reader_wake_ms": float64(woke) / float64(time.Millisecond),
		"registrar_exit_code": regCode, "creator_exit_code": creatorCode,
		"guards_preserved": len(guards), "adapter_present_after_removal": present})
}

// ---- proof B: engine crash with a real, traffic-carrying registration ----

// This process creates and configures the adapter and keeps it (its SwDevice
// lifetime handle), so the device survives an engine crash. A child process
// stands in for the engine: it opens the adapter, starts a production registrar
// session, carries real packets, and holds it. Terminating that child reaps its
// registrar (through kill-on-close and the closed control pipe), and the driver
// releases the registration on the registrar's process exit
// (TunProcessNotification -> force unregister -> both markers). Because this
// process still owns the present adapter, a single fresh production session
// that then re-registers and carries traffic proves the registration was
// released, not that the adapter disappeared. Any failure is hard: no tolerance
// loop can hide a driver (or a release path) that failed to free the device.
func TestWintunRegistrarEngineCrashReleasesRealRegistration(t *testing.T) {
	a := newAdapter(t, MinCapacity) // Create + IP config; requireRunner inside; t.Cleanup a.Close
	instance := a.InstanceID()
	engine := startChild(t, "TestWintunRegistrarRealEngineHolderChild", "NETSWITCH_WINTUN_REAL_ENGINE_HOLDER="+a.config.GUID,
		[]string{"HOLDER_READY "}, nil)
	regPID, err := strconv.ParseUint(engine.await(t, "HOLDER_READY ", 30*time.Second), 10, 32)
	must(t, err)
	enginePID := uint32(engine.cmd.Process.Pid)

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
	if !pnpPresent(t, instance) {
		t.Fatal("the adapter was not present before the engine crash")
	}

	started := ticks()
	must(t, engine.cmd.Process.Kill())
	exited, code := exitState(registrar, 10*time.Second)
	if !exited {
		t.Fatal("the registrar outlived the crashed engine; its real registration was not reaped")
	}
	reaped := elapsed(started)
	engineCode := engine.join(t, 10*time.Second) // reap the actual engine child before the final report
	// The adapter must still be present: this process owns it, so the recovery
	// below is attributable to the driver releasing the registration.
	presentAfterCrash := pnpPresent(t, instance)
	if !presentAfterCrash {
		t.Fatal("the adapter disappeared with the crashed engine; release cannot be distinguished from removal")
	}

	recoveryStart := ticks()
	f := fixtureOnAdapter(t, "ours", a) // one fresh production session; fatal on any failure
	exchange(t, 16)
	f.stopEcho()
	if f.faults.Load() != 0 {
		t.Fatalf("the re-registered production session failed: %v", f.fault())
	}
	recovered := elapsed(recoveryStart)
	report(t, map[string]any{"test": "registrar_engine_crash_real_registration", "arch": runtime.GOARCH,
		"registrar_pid": regPID, "engine_pid": enginePID, "registrar_exit_code": code, "engine_exit_code": engineCode,
		"registrar_reaped_after_crash_ms": float64(reaped) / float64(time.Millisecond),
		"recovery_ms":                     float64(recovered) / float64(time.Millisecond),
		"adapter_present_after_crash":     presentAfterCrash, "session_faults": f.faults.Load()})
}
