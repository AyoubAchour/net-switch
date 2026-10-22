//go:build windows

package wintun

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

func TestRegistrarReplyPreservesReadError(t *testing.T) {
	readErr := errors.New("reply owner close failed")
	for _, tc := range []struct {
		name, output string
	}{
		{"ready", registrarReplyPrefix + `{"ready":true,"memoryType":262144}`},
		{"rejected", registrarReplyPrefix + `{"stage":"register","errno":5,"error":"denied"}`},
		{"wrong memory", registrarReplyPrefix + `{"ready":true,"memoryType":0}`},
		{"invalid JSON", registrarReplyPrefix + `{`},
		{"missing prefix", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseReply([]byte(tc.output), readErr)
			if !errors.Is(err, readErr) {
				t.Fatalf("reply lost the reader/close error: %v", err)
			}
			if tc.name == "rejected" && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
				t.Fatalf("reply lost the child's registration error: %v", err)
			}
		})
	}
	if _, err := parseReply([]byte(registrarReplyPrefix+`{"ready":true,"memoryType":262144}`), nil); err != nil {
		t.Fatalf("valid ready reply failed without a reader error: %v", err)
	}
}

var (
	getProcessIDOfThread = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessIdOfThread")
	getExitCodeThread    = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetExitCodeThread")
)

// processThreads lists the IDs of this process's running threads. A handle
// diff alone can miss a new thread: Wintun job 119624723115 saw the handles a
// new Go M creates (two events, a wait timer, a wait completion packet) but no
// new thread handle, most likely because the M's duplicated thread handle
// reused a value closed after the baseline. Thread IDs do not depend on
// handle values.
func processThreads(t *testing.T) map[uint32]bool {
	t.Helper()
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(snapshot)
	self := windows.GetCurrentProcessId()
	threads := map[uint32]bool{}
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	for err = windows.Thread32First(snapshot, &entry); err == nil; err = windows.Thread32Next(snapshot, &entry) {
		if entry.OwnerProcessID == self {
			threads[entry.ThreadID] = true
		}
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		t.Fatal(err)
	}
	return threads
}

// newThreadIDs counts threads in after that were not running before.
func newThreadIDs(before, after map[uint32]bool) int {
	n := 0
	for id := range after {
		if !before[id] {
			n++
		}
	}
	return n
}

// newLiveThreads counts handles in after but not before that are threads of
// this process which are still running.
func newLiveThreads(t *testing.T, before, after map[windows.Handle]bool) int {
	t.Helper()
	const stillActive = 259
	live := 0
	for h := range after {
		if before[h] {
			continue
		}
		if kind, err := objectType(h); err != nil || kind != "Thread" {
			continue
		}
		pid, _, _ := getProcessIDOfThread.Call(uintptr(h))
		var code uint32
		ok, _, _ := getExitCodeThread.Call(uintptr(h), uintptr(unsafe.Pointer(&code)))
		if uint32(pid) == windows.GetCurrentProcessId() && ok != 0 && code == stillActive {
			live++
		}
	}
	return live
}

// Exercise real suspended/running children and pipe reads. Each injected close
// first closes its actual owned handle successfully, then reports an error:
// the caller must propagate that error and must never retry the consumed owner.
func TestWintunRegistrarStartupCloseErrors(t *testing.T) {
	cases := []struct {
		name, site, fault string
		threadError       bool
	}{
		{"inherited and thread", "Wintun registrar inherited duplicate close", "", true},
		{"parent pipe and thread", "Wintun registrar control read close", "", true},
		{"ready reply", "Wintun registrar reply read close", "", false},
		{"timeout reply", "Wintun registrar reply read close", "hang", false},
	}
	// Every case runs twice. The first pass gets every assertion except the
	// handle delta, which it only logs: run first in a fresh process (the
	// ordinary Wintun job, run 39564185852), it counted one-time lazy handles
	// (ETW registrations, a registry key, a new Go thread's events) as leaks.
	// The second pass runs the same paths again and fails on any new handle,
	// so a leak per failed start still shows.
	type run struct {
		pass    int
		enforce bool
	}
	var runs []run
	for pass, enforce := range []bool{false, true} {
		for range cases {
			runs = append(runs, run{pass + 1, enforce})
		}
	}
	for i, current := range runs {
		tc, enforce := cases[i%len(cases)], current.enforce
		t.Run(fmt.Sprintf("pass%d/%s", current.pass, tc.name), func(t *testing.T) {
			originalClose, originalCommand, originalEnv := registrarClose, registrarCommand, registrarExtraEnv
			originalTimeout := registrarStartTimeout
			var mu sync.Mutex
			var child windows.Handle
			var witnessErr, nativeCloseErr error
			seen := map[winhandle.Owner]bool{}
			injected, threadInjected, repeated := false, false, false
			closeErr, threadErr := errors.New("injected startup close error"), errors.New("injected primary thread close error")
			defer func() {
				registrarClose, registrarCommand, registrarExtraEnv = originalClose, originalCommand, originalEnv
				registrarStartTimeout = originalTimeout
				if child != 0 {
					windows.CloseHandle(child)
				}
			}()
			registrarCommand = registrarFixtureMode
			registrarExtraEnv = []string{"NETSWITCH_WINTUN_FIXTURE_FAULT=" + tc.fault}
			if tc.fault == "hang" {
				registrarStartTimeout = 100 * time.Millisecond
			}
			registrarClose = func(o winhandle.Owner, site string) error {
				mu.Lock()
				defer mu.Unlock()
				if seen[o] {
					repeated = true
					return errors.New("startup retried a consumed handle owner")
				}
				seen[o] = true
				return o.Close(site, func(h windows.Handle) error {
					if site == "Wintun registrar setup process close" {
						witnessErr = windows.DuplicateHandle(windows.CurrentProcess(), h, windows.CurrentProcess(), &child, 0, false, windows.DUPLICATE_SAME_ACCESS)
					}
					err := windows.CloseHandle(h)
					nativeCloseErr = errors.Join(nativeCloseErr, err)
					if site == tc.site && !injected {
						injected = true
						err = errors.Join(err, closeErr)
					}
					if site == "Wintun registrar thread close" && tc.threadError {
						threadInjected = true
						err = errors.Join(err, threadErr)
					}
					return err
				})
			}
			warmRuntimeThreads()
			before := handleSnapshot(t)
			beforeThreads := processThreads(t)
			r, err := allocateRings(MinCapacity)
			must(t, err)
			defer r.close()
			must(t, r.createEvents())
			g, startErr := startRegistrar(`\\?\SWD#Wintun#{00000000-0000-0000-0000-000000000000}#{cac88484-7515-4c03-82e6-71a87aba61c3}`, r)
			if g != nil {
				g.retire(windows.CloseHandle)
				t.Fatal("startup accepted an injected close failure")
			}
			mu.Lock() // the reply reader also invokes the close seam
			defer mu.Unlock()
			if !injected || !errors.Is(startErr, closeErr) || (tc.threadError && (!threadInjected || !errors.Is(startErr, threadErr))) {
				t.Fatalf("startup discarded a cleanup error: injected=%v thread=%v error=%v", injected, threadInjected, startErr)
			}
			if tc.fault == "hang" && !strings.Contains(startErr.Error(), "did not report") {
				t.Fatalf("timeout reader result replaced the timeout cause: %v", startErr)
			}
			if repeated || nativeCloseErr != nil {
				t.Fatalf("cleanup did not consume each actual owner once: repeated=%v native=%v", repeated, nativeCloseErr)
			}
			if witnessErr != nil || child == 0 {
				t.Fatalf("failed startup child was not independently witnessed: %v", witnessErr)
			}
			if exited, _ := exitState(child, time.Second); !exited {
				t.Fatal("failed startup child is still alive")
			}
			childCloseErr := windows.CloseHandle(child)
			child = 0
			must(t, childCloseErr)
			must(t, r.close())
			after := handleSnapshot(t)
			kinds := newHandleKinds(t, before, after)
			// A new OS thread in this process (Go runtime or Windows thread
			// pool) brings its own handles: run 39587194026 saw exactly one
			// thread, two events, two high-resolution timers and one wait
			// completion packet. Attribute at most two new events to each
			// new handle that is a live thread of this process; any other
			// event, and every other kind, is still a leak. New threads are
			// counted both by handle and by thread ID; the larger count wins.
			threads := max(newLiveThreads(t, before, after), newThreadIDs(beforeThreads, processThreads(t)))
			events := kinds["Event"]
			if threadEvents := min(events, 2*threads); threadEvents != 0 {
				t.Logf("new events attributed to %d new live thread(s) of this process: %d of %d old_pass=false", threads, threadEvents, events)
				kinds["Event"] -= threadEvents
			}
			for _, kind := range []string{"Section", "Job", "File", "Pipe", "Process", "Event", "unreadable"} {
				if kinds[kind] != 0 {
					if !enforce {
						t.Logf("warm-up pass new handles %v old_pass=false (not enforced; the second pass is)", kinds)
						break
					}
					t.Fatalf("startup close failure leaked handles: %v", kinds)
				}
			}
		})
	}
}
