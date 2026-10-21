package lifecycle_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/lifecycle"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/internal/service"
	"golang.org/x/sys/windows"
)

// ntZeroOpen opens the client side of a pipe with a *truly* empty access mask
// through NtCreateFile. Win32 CreateFile(0) silently adds SYNCHRONIZE and
// FILE_READ_ATTRIBUTES, so it cannot express the zero-access idle open a
// hostile user would attempt against the private desktop pipe. FILE_OPEN with
// no FILE_SYNCHRONOUS_IO_* option means the handle never needs SYNCHRONIZE.
func ntZeroOpen(ntPath string) (windows.Handle, error) {
	name, err := windows.NewNTUnicodeString(ntPath)
	if err != nil {
		return 0, err
	}
	oa := windows.OBJECT_ATTRIBUTES{ObjectName: name, Attributes: windows.OBJ_CASE_INSENSITIVE}
	oa.Length = uint32(unsafe.Sizeof(oa))
	var h windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&h, 0, &oa, &iosb, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE, 0, 0)
	if err != nil {
		return 0, err
	}
	return h, nil
}

func ntPipePath(kind string) string {
	// \\.\pipe\NAME maps to the NT object path \??\pipe\NAME.
	return `\??\` + strings.TrimPrefix(localipc.DefaultPath(kind), `\\.\`)
}

// idleAdmissionFlood is the hostile medium-integrity subprocess. It runs two
// independent worker pools so a private-pipe result can never mask a genuine
// public-pipe open (or the reverse):
//
//   - public workers continuously open the status pipe with read/write access
//     and never send the one identity byte. The server accepts, creates its
//     replacement instance and then parks in a 250 ms preamble read before
//     closing the connection, so a steady stream of these opens keeps the
//     public accept loop permanently busy. Opens are inherently throttled to
//     that accept rate, which is exactly the sustained pressure being modelled.
//   - private workers attempt zero-access NtCreateFile opens of the desktop
//     pipe. A success proves a medium, non-owner user can reach the private
//     pipe with an empty access mask (Win32 CreateFile cannot express this);
//     denials are counted separately.
//
// A bounded number of successful opens of each kind are held open as durable
// evidence; the rest are closed immediately so the pools can keep opening
// without exhausting handles. One machine-readable ready line is printed once
// the public flood is proven active, after which both pools keep running until
// stdin closes.
func idleAdmissionFlood() error {
	if lifecycle.Administrator() {
		return errors.New("admission flood was not a standard user")
	}
	const evidenceCap = 128
	var publicConnected, privateConnected, privateDenied, privateHeld atomic.Int64
	var held struct {
		sync.Mutex
		handles []windows.Handle
	}
	keep := func(h windows.Handle) bool {
		held.Lock()
		defer held.Unlock()
		if len(held.handles) >= 2*evidenceCap {
			return false
		}
		held.handles = append(held.handles, h)
		return true
	}
	defer func() {
		held.Lock()
		for _, h := range held.handles {
			windows.CloseHandle(h)
		}
		held.Unlock()
	}()

	statusPath, _ := windows.UTF16PtrFromString(localipc.DefaultPath("status"))
	desktopNT := ntPipePath("desktop")
	stop := make(chan struct{})
	var workers sync.WaitGroup

	for range 6 {
		workers.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				h, err := windows.CreateFile(statusPath, windows.FILE_READ_DATA|windows.FILE_WRITE_DATA, 0, nil, windows.OPEN_EXISTING, windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
				if err == nil {
					publicConnected.Add(1)
					if publicConnected.Load() > evidenceCap || !keep(h) {
						windows.CloseHandle(h)
					}
				} else if err == windows.ERROR_PIPE_BUSY {
					time.Sleep(2 * time.Millisecond)
				}
			}
		})
	}
	for range 4 {
		workers.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				h, err := ntZeroOpen(desktopNT)
				if err == nil {
					privateConnected.Add(1)
					if keep(h) {
						privateHeld.Add(1)
					} else {
						windows.CloseHandle(h)
					}
				} else {
					privateDenied.Add(1)
					time.Sleep(2 * time.Millisecond)
				}
			}
		})
	}

	deadline := time.Now().Add(15 * time.Second)
	for publicConnected.Load() < 64 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	// Give the private pool a brief settling window so the ready line reports a
	// meaningful connected/denied split rather than a first-attempt snapshot.
	settle := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(settle) {
		time.Sleep(20 * time.Millisecond)
	}
	pub := publicConnected.Load()
	if pub < 64 {
		close(stop)
		workers.Wait()
		return fmt.Errorf("public flood never took hold: public_connected=%d", pub)
	}
	fmt.Printf("admission flood ready public_connected=%d private_connected=%d private_held=%d private_denied=%d\n", pub, privateConnected.Load(), privateHeld.Load(), privateDenied.Load())

	// Sustain both pools until the parent has finished its owner probes.
	_, _ = io.Copy(io.Discard, os.Stdin)
	before := publicConnected.Load()
	close(stop)
	workers.Wait()
	grew := publicConnected.Load() - before
	if grew < 32 {
		return fmt.Errorf("public flood stalled while held: only %d further opens", grew)
	}
	fmt.Printf("admission flood sustained public_connected=%d private_connected=%d private_held=%d private_denied=%d\n", publicConnected.Load(), privateConnected.Load(), privateHeld.Load(), privateDenied.Load())
	return nil
}

type floodVerdict struct {
	publicConnected, privateConnected, privateHeld, privateDenied int64
}

func parseFloodReady(line string) (floodVerdict, bool) {
	var v floodVerdict
	if !strings.HasPrefix(line, "admission flood ready ") {
		return v, false
	}
	for _, field := range strings.Fields(strings.TrimSpace(line)) {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			continue
		}
		switch key {
		case "public_connected":
			v.publicConnected = n
		case "private_connected":
			v.privateConnected = n
		case "private_held":
			v.privateHeld = n
		case "private_denied":
			v.privateDenied = n
		}
	}
	return v, true
}

// idleAdmissionCapacity drives the probe: a hostile standard user floods the
// public status pipe (and attempts the private desktop pipe) with idle opens,
// and the owner and administrator must still complete their protected-endpoint
// operations while every hostile handle is held open.
func idleAdmissionCapacity(t *testing.T, dir, data string, owner, other actor) {
	t.Helper()
	exe, _ := os.Executable()
	attack := other.command(exe, "client", "admission-flood")
	input, err := attack.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := attack.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var diagnostics bytes.Buffer
	attack.Stderr = &diagnostics
	if err := attack.Start(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(out)
	exit := make(chan error, 1)
	go func() { exit <- attack.Wait() }()
	exited := false
	waitExit := func() error {
		if exited {
			return nil
		}
		exited = true
		return <-exit
	}
	released := false
	release := func() {
		if !released {
			released = true
			input.Close()
		}
	}
	defer func() { release(); _ = attack.Process.Kill(); _ = waitExit() }()

	ready, err := reader.ReadString('\n')
	verdict, ok := parseFloodReady(ready)
	if err != nil || !ok {
		t.Fatal("admission flood precondition", ready, err, diagnostics.String())
	}
	if verdict.publicConnected < 64 {
		t.Fatalf("public flood not independently observed: %+v", verdict)
	}
	t.Logf("hostile flood active: public_connected=%d private_connected=%d private_held=%d private_denied=%d", verdict.publicConnected, verdict.privateConnected, verdict.privateHeld, verdict.privateDenied)
	if verdict.privateConnected > 0 {
		// A zero-access open of the private pipe succeeded. The protected-first
		// readers still have to admit the owner while that pool keeps hammering
		// the desktop accept loop; this is asserted below, never waved through.
		t.Logf("NOTE: %d zero-access private desktop opens succeeded (%d held); owner admission is required to survive them", verdict.privateConnected, verdict.privateHeld)
	}

	ctl := filepath.Join(dir, binary("netswitchctl"))

	// Owner CLI status (protected endpoint, must not activate or block).
	ownerStatus := make(chan error, 1)
	go func() {
		b, err := owner.command(ctl, "status").CombinedOutput()
		if err != nil {
			ownerStatus <- fmt.Errorf("owner status: %w: %s", err, b)
			return
		}
		ownerStatus <- nil
	}()

	// Fresh owner desktop session established entirely during the flood.
	fresh := openClient(t, owner, false)
	var session struct {
		Token string `json:"token"`
		URL   string `json:"url"`
	}
	fresh.must(t, "session", nil, &session)

	// Administrator re-enrollment runs its protected settle check during the
	// flood. The harness process is SYSTEM, i.e. an elevated administrator.
	enrollCtx, cancelEnroll := context.WithTimeout(context.Background(), 40*time.Second)
	enrolled := make(chan error, 1)
	go func() {
		cmd := exec.CommandContext(enrollCtx, ctl, "enroll", "--data", data, "--owner", owner.id())
		b, err := cmd.CombinedOutput()
		if err != nil {
			enrolled <- fmt.Errorf("admin enroll: %w: %s", err, b)
			return
		}
		enrolled <- nil
	}()

	select {
	case err := <-ownerStatus:
		if err != nil {
			cancelEnroll()
			t.Fatal(err)
		}
	case <-time.After(35 * time.Second):
		cancelEnroll()
		t.Fatal("owner CLI status blocked during flood")
	}
	select {
	case err := <-enrolled:
		cancelEnroll()
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(45 * time.Second):
		cancelEnroll()
		t.Fatal("administrator enrollment blocked during flood")
	}
	cancelEnroll()

	// Prove the flood was still being held while every owner probe ran.
	select {
	case werr := <-exit:
		exited = true
		t.Fatal("flood ended before owner admission was proved", werr, diagnostics.String())
	default:
	}

	// Owner token issued during the flood actually works end to end.
	if code, _ := apiAs(t, owner, session.URL, session.Token, "GET", "/api/state", ""); code != 200 {
		t.Fatalf("owner token blocked during flood: %d", code)
	}
	fresh.input.Close()

	release()
	if err := waitExit(); err != nil {
		t.Fatal(err, diagnostics.String())
	}
	t.Log("owner CLI, fresh desktop, token and administrator enrollment all completed while the idle-open flood was held")
	t.Log(strings.TrimSpace(diagnostics.String()))

	// Services were never restarted by the flood.
	if s, err := service.Query(service.Control); err != nil || !s.Running {
		t.Fatalf("Control not healthy after flood: %+v err=%v", s, err)
	}
}
