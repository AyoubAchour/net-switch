//go:build windows

package wintun

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// These tests need no adapter: the registrar must refuse to run as a stray
// process, and must refuse inherited handles of the wrong kind.
func runRegistrarChild(t *testing.T, config *registrarConfig, inherit []syscall.Handle) (int, string) {
	t.Helper()
	exe, err := os.Executable()
	must(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, RegistrarMode)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, AdditionalInheritedHandles: inherit}
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if config != nil {
		encoded, err := json.Marshal(config)
		must(t, err)
		cmd.Stdin = bytes.NewReader(append(encoded, '\n')) // os/exec passes a pipe
	}
	err = cmd.Run()
	var exited *exec.ExitError
	if err != nil && !errors.As(err, &exited) {
		t.Fatal(err)
	}
	return cmd.ProcessState.ExitCode(), output.String()
}

func TestRegistrarRefusesWithoutInheritedCapabilities(t *testing.T) {
	// No configuration: os/exec gives the NUL device, not a pipe.
	if code, output := runRegistrarChild(t, nil, nil); code != 2 || !strings.Contains(output, "requires the engine's inherited pipes") {
		t.Fatalf("stray registrar ran: code %d, %q", code, output)
	}
	var events [3]windows.Handle
	for i := range events {
		h, err := windows.CreateEvent(nil, 0, 0, nil)
		must(t, err)
		defer windows.CloseHandle(h)
		must(t, windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT))
		events[i] = h
	}
	valid := registrarConfig{Version: registrarVersion, Capacity: MinCapacity, ViewBytes: uint64(viewBytes(MinCapacity)),
		Path:    `\\?\SWD#Wintun#{00000000-0000-0000-0000-000000000000}#{cac88484-7515-4c03-82e6-71a87aba61c3}`,
		Section: uint64(events[0]), Read: uint64(events[1]), Write: uint64(events[2])}
	inherit := []syscall.Handle{syscall.Handle(events[0]), syscall.Handle(events[1]), syscall.Handle(events[2])}
	for _, tc := range []struct {
		name, stage, text string
		edit              func(*registrarConfig)
		inherit           []syscall.Handle
	}{
		{"wrong version", "configuration", "unsupported", func(c *registrarConfig) { c.Version++ }, inherit},
		{"wrong view size", "configuration", "unsupported", func(c *registrarConfig) { c.ViewBytes += 4096 }, inherit},
		{"foreign device path", "configuration", "not a Wintun device", func(c *registrarConfig) { c.Path = `\\?\PhysicalDrive0` }, inherit},
		{"repeated handle", "inheritance", "not distinct", func(c *registrarConfig) { c.Read = c.Write }, inherit},
		{"event as section", "inheritance", `not "Section"`, func(*registrarConfig) {}, inherit},
		{"handles not inherited", "inheritance", "inherited handle", func(*registrarConfig) {}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := valid
			tc.edit(&config)
			code, output := runRegistrarChild(t, &config, tc.inherit)
			reply, err := parseReply([]byte(strings.TrimSpace(output)), nil)
			if code != 1 || err == nil || reply.Stage != tc.stage || !strings.Contains(reply.Error, tc.text) {
				t.Fatalf("code %d, reply %+v, err %v, output %q", code, reply, err, output)
			}
		})
	}
}

func handleSnapshot(t *testing.T) map[windows.Handle]bool {
	t.Helper()
	data := make([]uint64, 1<<17) // 1 MiB, pointer-aligned
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&data[0])), len(data)*8)
	var used uint32
	must(t, windows.NtQueryInformationProcess(windows.CurrentProcess(), windows.ProcessHandleInformation, unsafe.Pointer(&data[0]), uint32(len(raw)), &used))
	count := binary.LittleEndian.Uint64(raw[:8])
	if count > uint64((len(raw)-16)/40) {
		t.Fatal("invalid process handle snapshot")
	}
	values := map[windows.Handle]bool{}
	for i := uint64(0); i < count; i++ {
		values[windows.Handle(binary.LittleEndian.Uint64(raw[16+i*40:]))] = true
	}
	return values
}

// assertNoDeviceHandle classifies every handle the session added to this
// process. The only file-type handle a session may own is its control pipe.
func assertNoDeviceHandle(t *testing.T, before, after map[windows.Handle]bool) map[string]int {
	t.Helper()
	kinds := map[string]int{}
	for h := range after {
		if before[h] {
			continue
		}
		kind, err := objectType(h)
		if err != nil {
			kinds["closed during snapshot"]++
			continue
		}
		kinds[kind]++
		if kind == "File" && !isPipe(h) {
			fileType, _ := windows.GetFileType(h)
			t.Fatalf("session left a non-pipe file handle %#x (file type %d) in the engine process", h, fileType)
		}
	}
	return kinds
}

func sessionRegistrar(t *testing.T, s *Session) (*registrar, windows.Handle) {
	t.Helper()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.rings == nil {
		t.Fatal("session has no rings")
	}
	g, ok := s.rings.owner.(*registrar)
	if !ok {
		t.Fatalf("session rings are owned by %T, not a registrar", s.rings.owner)
	}
	return g, witness(t, g.process.Handle("test registrar witness"))
}

func exitState(process windows.Handle, wait time.Duration) (bool, uint32) {
	result, err := windows.WaitForSingleObject(process, uint32(wait/time.Millisecond))
	var code uint32
	windows.GetExitCodeProcess(process, &code)
	return err == nil && result == windows.WAIT_OBJECT_0, code
}

func exchange(t *testing.T, rounds int) {
	t.Helper()
	c := udpSocket(t)
	defer c.Close()
	reply := make([]byte, 2048)
	for round := range rounds {
		payload := bytes.Repeat([]byte{byte(round), 0x5a, 0xc3}, 200)
		must(t, c.SetDeadline(time.Now().Add(time.Second)))
		_, err := c.Write(payload)
		must(t, err)
		n, err := c.Read(reply)
		must(t, err)
		if !bytes.Equal(payload, reply[:n]) {
			t.Fatal("registrar session packet corruption")
		}
	}
}

// Production capacity (8 MiB rings), unchanged packet path. The engine process
// must hold no device handle; the registrar reports its own footprint.
func TestWintunRegistrarSession(t *testing.T) {
	requireRunner(t)
	// The baseline excludes the DLL's guarded image file, but includes the
	// adapter's creation: any handle the DLL keeps to the device counts too.
	_, err := loadLibrary()
	must(t, err)
	warmRuntimeThreads()
	before := handleSnapshot(t)
	a := newAdapter(t, 0)
	f := fixtureOnAdapter(t, "ours", a)
	after := handleSnapshot(t)
	kinds := assertNoDeviceHandle(t, before, after)
	s := f.io.(*Session)
	_, process := sessionRegistrar(t, s)
	defer windows.CloseHandle(process)
	exchange(t, 64)
	f.stopEcho()
	if f.faults.Load() != 0 {
		t.Fatalf("registrar session packet path failed: %v", f.fault())
	}
	stats := s.Stats()
	must(t, s.Close())
	exited, code := exitState(process, 0)
	closed := s.Stats().CloseDetails
	// Re-registration on the same adapter proves the driver released it.
	again, err := a.StartSession()
	must(t, err)
	must(t, again.Close())
	report(t, map[string]any{"test": "registrar_session", "arch": runtime.GOARCH, "capacity": a.config.Capacity,
		"new_engine_handles": kinds, "registrar": stats.Registrar, "registrar_start_ms": float64(stats.Registrar.StartNanos) / 1e6,
		"read_waits": stats.ReadWaits, "read_wakes": stats.ReadWakes, "exchanges": 64,
		"registrar_exited": exited, "registrar_exit_code": code,
		"retire_ms": float64(closed.DeviceNanos) / 1e6, "driver_wait_ms": float64(closed.DriverWaitNanos) / 1e6})
	if stats.Registrar.Starts != 1 || stats.Registrar.PID == 0 || stats.Registrar.PrivateBytes == 0 {
		t.Fatalf("registrar statistics missing: %+v", stats.Registrar)
	}
	if !exited || code != 0 {
		t.Fatalf("registrar did not exit cleanly after Close: exited=%v code=%#x", exited, code)
	}
}

type sessionLoss struct {
	reader  chan error
	guards  [][2]windows.Handle
	process windows.Handle
}

func watchLoss(t *testing.T, s *Session) *sessionLoss {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	l := &sessionLoss{reader: make(chan error, 1)}
	_, l.process = sessionRegistrar(t, s)
	t.Cleanup(func() { windows.CloseHandle(l.process) })
	waits := s.Stats().ReadWaits
	go func() {
		buf := make([]byte, MaxPacketSize)
		for {
			if _, err := s.ReadPacket(ctx, buf); err != nil {
				l.reader <- err
				return
			}
		}
	}()
	// Reader only: the loss must wake a parked reader without write traffic.
	for s.Stats().ReadWaits == waits {
		if ctx.Err() != nil {
			t.Fatal("reader never parked")
		}
		time.Sleep(time.Millisecond)
	}
	for range 32 {
		h := testEvent(t)
		l.guards = append(l.guards, [2]windows.Handle{h, witness(t, h)})
	}
	t.Cleanup(func() {
		for _, g := range l.guards {
			if sameObject(g[0], g[1]) {
				windows.CloseHandle(g[0])
			}
			windows.CloseHandle(g[1])
		}
	})
	return l
}

func (l *sessionLoss) wait(t *testing.T, registrarExit bool) error {
	t.Helper()
	var err error
	select {
	case err = <-l.reader:
	case <-time.After(10 * time.Second):
		t.Fatal("session loss left the reader parked")
	}
	if !errors.Is(err, ErrAdapterRemoved) || errors.Is(err, ErrRegistrarExited) != registrarExit {
		t.Fatalf("reader error %v: want ErrAdapterRemoved, registrar exit %v", err, registrarExit)
	}
	for i, g := range l.guards {
		if !sameObject(g[0], g[1]) || windows.SetEvent(g[0]) != nil {
			t.Fatalf("session loss closed or replaced unrelated engine handle %d", i)
		}
	}
	return err
}

var (
	locateDevNode      = windows.NewLazySystemDLL("cfgmgr32.dll").NewProc("CM_Locate_DevNodeW")
	queryAndRemoveTree = windows.NewLazySystemDLL("cfgmgr32.dll").NewProc("CM_Query_And_Remove_SubTreeW")
)

func queryRemove(t *testing.T, instance string) {
	t.Helper()
	id, err := windows.UTF16PtrFromString(instance)
	must(t, err)
	var node uint32
	if cr, _, _ := locateDevNode.Call(uintptr(unsafe.Pointer(&node)), uintptr(unsafe.Pointer(id)), 0); cr != 0 {
		t.Fatalf("CM_Locate_DevNode %s: CR %#x", instance, cr)
	}
	var veto uint32
	name := make([]uint16, 512)
	const removeUINotOK, removeNoRestart = 0x1, 0x2
	if cr, _, _ := queryAndRemoveTree.Call(uintptr(node), uintptr(unsafe.Pointer(&veto)), uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)), removeUINotOK|removeNoRestart); cr != 0 {
		t.Fatalf("query-remove refused: CR %#x, veto type %d by %q", cr, veto, windows.UTF16ToString(name))
	}
}

func TestWintunRegistrarOwnerChild(t *testing.T) {
	guid := os.Getenv("NETSWITCH_WINTUN_OWNER_GUID")
	if guid == "" {
		t.Skip("adapter owner child only")
	}
	requireRunner(t)
	a, err := Create(Config{Name: "NsRingOwnerCI", GUID: guid, Capacity: MinCapacity})
	must(t, err)
	fmt.Println("OWNER_READY " + a.InstanceID())
	for {
		time.Sleep(time.Hour)
	}
}

func readyLine(t *testing.T, cmd *exec.Cmd, prefix string) string {
	t.Helper()
	pipe, err := cmd.StdoutPipe()
	must(t, err)
	cmd.Stderr = os.Stderr
	must(t, cmd.Start())
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	found := make(chan string, 1)
	go func() {
		scan := bufio.NewScanner(pipe)
		for scan.Scan() {
			if strings.HasPrefix(scan.Text(), prefix) {
				found <- strings.TrimPrefix(scan.Text(), prefix)
				break
			}
		}
		close(found)
		for scan.Scan() { // keep draining
		}
	}()
	select {
	case line, ok := <-found:
		if !ok {
			t.Fatalf("child exited before %q", prefix)
		}
		return line
	case <-time.After(30 * time.Second):
		t.Fatalf("child did not report %q", prefix)
	}
	return ""
}

// Each loss ends the session through ErrAdapterRemoved without a recovery
// failure. Registrar death leaves the adapter usable; removal does not.
func TestWintunRegistrarLoss(t *testing.T) {
	requireRunner(t)
	for _, kind := range []string{"registrar-terminate", "job-terminate"} {
		t.Run(kind, func(t *testing.T) {
			a := newAdapter(t, MinCapacity)
			s, err := a.StartSession()
			must(t, err)
			defer s.Close()
			l := watchLoss(t, s)
			g, w := sessionRegistrar(t, s)
			windows.CloseHandle(w)
			started := ticks()
			if kind == "job-terminate" {
				must(t, windows.TerminateJobObject(g.job.Handle("test job termination"), 0xdead))
			} else {
				must(t, windows.TerminateProcess(g.process.Handle("test registrar termination"), 0xdead))
			}
			err = l.wait(t, true)
			lost := elapsed(started)
			exited, code := exitState(l.process, time.Second)
			if !exited || code != 0xdead {
				t.Fatalf("registrar was not terminated: exited=%v code=%#x", exited, code)
			}
			must(t, s.Close())
			if stats := s.Stats(); stats.RecoveryFailures != 0 || stats.Recoveries != 0 {
				t.Fatalf("registrar loss counted as recovery: %+v", stats)
			}
			if _, _, err := deviceForGUID(mustGUID(t, a.config.GUID)); err != nil {
				t.Fatalf("adapter disappeared with its registrar: %v", err)
			}
			f := fixtureOnAdapter(t, "ours", a)
			exchange(t, 16)
			f.stopEcho()
			report(t, map[string]any{"test": "registrar_loss", "arch": runtime.GOARCH, "kind": kind, "error": err.Error(),
				"reader_wake_ms": float64(lost) / float64(time.Millisecond), "guards_preserved": len(l.guards), "reregistered": true})
		})
	}
	t.Run("query-remove", func(t *testing.T) {
		a := newAdapter(t, MinCapacity)
		s, err := a.StartSession()
		must(t, err)
		defer s.Close()
		l := watchLoss(t, s)
		started := ticks()
		queryRemove(t, a.InstanceID())
		err = l.wait(t, false)
		lost := elapsed(started)
		must(t, s.Close())
		exited, code := exitState(l.process, 0)
		if !exited || code != 0 {
			t.Fatalf("registrar did not exit on its stop request after removal: exited=%v code=%#x", exited, code)
		}
		instance := a.InstanceID()
		must(t, a.Close())
		assertPnPAbsent(t, instance)
		report(t, map[string]any{"test": "registrar_loss", "arch": runtime.GOARCH, "kind": "query-remove", "error": err.Error(),
			"reader_wake_ms": float64(lost) / float64(time.Millisecond), "guards_preserved": len(l.guards)})
	})
	t.Run("creator-death-surprise-removal", func(t *testing.T) {
		guid, err := windows.GenerateGUID()
		must(t, err)
		exe, err := os.Executable()
		must(t, err)
		owner := exec.Command(exe, "-test.run=^TestWintunRegistrarOwnerChild$", "-test.v")
		owner.Env = append(os.Environ(), "NETSWITCH_WINTUN_OWNER_GUID="+guid.String())
		instance := readyLine(t, owner, "OWNER_READY ")
		config := Config{Name: "NsRingOwnerCI", GUID: guid.String(), Capacity: MinCapacity}
		borrowed, err := Open(config)
		must(t, err)
		defer borrowed.Close()
		s, err := borrowed.StartSession()
		must(t, err)
		defer s.Close()
		l := watchLoss(t, s)
		started := ticks()
		// The DLL ties the software device to its creator's handle; the
		// creator's death removes a started device without a query.
		must(t, owner.Process.Kill())
		err = l.wait(t, false)
		lost := elapsed(started)
		must(t, s.Close())
		exited, code := exitState(l.process, 0)
		if !exited || code != 0 {
			t.Fatalf("registrar did not exit on its stop request after removal: exited=%v code=%#x", exited, code)
		}
		must(t, borrowed.Close())
		removed, cleanupErr := recoverAfterCrash(config)
		must(t, cleanupErr)
		assertPnPAbsent(t, instance)
		report(t, map[string]any{"test": "registrar_loss", "arch": runtime.GOARCH, "kind": "creator-death-surprise-removal",
			"error": err.Error(), "reader_wake_ms": float64(lost) / float64(time.Millisecond),
			"guards_preserved": len(l.guards), "phantoms_removed": removed})
	})
}

func mustGUID(t *testing.T, text string) windows.GUID {
	t.Helper()
	guid, err := windows.GUIDFromString(text)
	must(t, err)
	return guid
}

func TestWintunRegistrarEngineChild(t *testing.T) {
	guid := os.Getenv("NETSWITCH_WINTUN_ENGINE_GUID")
	if guid == "" {
		t.Skip("engine child only")
	}
	requireRunner(t)
	a, err := Open(Config{Name: "NsRingCI", GUID: guid, Capacity: MinCapacity})
	must(t, err)
	s, err := a.StartSession()
	must(t, err)
	fmt.Printf("ENGINE_READY %d\n", s.Stats().Registrar.PID)
	for {
		time.Sleep(time.Hour)
	}
}

// An engine crash closes the only handle to the registrar's kill-on-close job,
// so the registrar dies with it and the driver releases the registration.
func TestWintunRegistrarEngineCrash(t *testing.T) {
	requireRunner(t)
	a := newAdapter(t, MinCapacity)
	exe, err := os.Executable()
	must(t, err)
	engine := exec.Command(exe, "-test.run=^TestWintunRegistrarEngineChild$", "-test.v")
	engine.Env = append(os.Environ(), "NETSWITCH_WINTUN_ENGINE_GUID="+a.config.GUID)
	pid, err := strconv.ParseUint(readyLine(t, engine, "ENGINE_READY "), 10, 32)
	must(t, err)
	// The engine is alive, so this PID still names its registrar.
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	must(t, err)
	defer windows.CloseHandle(h)
	name := make([]uint16, 4096)
	size := uint32(len(name))
	must(t, windows.QueryFullProcessImageName(h, 0, &name[0], &size))
	if !strings.EqualFold(windows.UTF16ToString(name[:size]), exe) {
		t.Fatalf("PID %d is %q, not the registrar image", pid, windows.UTF16ToString(name[:size]))
	}
	if exited, _ := exitState(h, 0); exited {
		t.Fatal("registrar exited before the engine crash")
	}
	started := ticks()
	must(t, engine.Process.Kill())
	exited, code := exitState(h, 5*time.Second)
	died := elapsed(started)
	if !exited {
		t.Fatal("registrar outlived the crashed engine")
	}
	// The adapter's registration slot is free again.
	f := fixtureOnAdapter(t, "ours", a)
	exchange(t, 16)
	f.stopEcho()
	report(t, map[string]any{"test": "registrar_engine_crash", "arch": runtime.GOARCH, "registrar_pid": pid,
		"registrar_exit_code": code, "registrar_exit_after_engine_kill_ms": float64(died) / float64(time.Millisecond), "reregistered": true})
}
