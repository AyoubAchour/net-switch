//go:build windows

package wintun

import (
	"errors"
	"fmt"
	"runtime/metrics"
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

// runtimeThreads reports how many OS threads the Go runtime owns, from the
// runtime's own bookkeeping (/sched/threads/total:threads, computed from
// mcount minus the extra Ms in runtime/metrics.go). It reports a new M before
// its OS thread exists: mcommoninit adds the M to allm while preemption is
// disabled and the thread is started only afterwards (runtime/proc.go). Extra
// Ms, used for callbacks on threads the runtime did not create, are excluded.
//
// This matters because the runtime gives every new M native handles that a
// handle diff cannot tell from a registrar's: minit creates two
// high-resolution timers and a wait completion packet (runtime/os_windows.go
// minit) and the M's first park creates its two semaphore events through
// semacreate (runtime/os_windows.go, called from lock_sema.go). Wintun job
// 120219177139 failed on exactly those five handles with no new thread handle
// and no new thread ID to attribute them to.
func runtimeThreads(t *testing.T) uint64 {
	t.Helper()
	sample := []metrics.Sample{{Name: "/sched/threads/total:threads"}}
	metrics.Read(sample)
	if kind := sample[0].Value.Kind(); kind != metrics.KindUint64 {
		t.Fatalf("runtime thread metric is %v, want uint64", kind)
	}
	return sample[0].Value.Uint64()
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
			time.Sleep(10 * time.Millisecond) // let every warmed M park and create its semaphore events
			before := handleSnapshot(t)
			beforeThreads := processThreads(t)
			beforeRuntimeThreads := runtimeThreads(t)
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
			// Give an M the pass just started time to park: it creates its two
			// semaphore events only when it first parks, and they belong to
			// this measurement rather than the next one.
			time.Sleep(10 * time.Millisecond)
			after := handleSnapshot(t)
			afterRuntimeThreads := runtimeThreads(t)
			kinds := newHandleKinds(t, before, after)
			// A new Go M brings its own handles, and the registrar creates
			// none of those kinds: every M gets two high-resolution timers and
			// a wait completion packet from minit (runtime/os_windows.go) and
			// two semaphore events from semacreate the first time it parks
			// (runtime/os_windows.go, called from lock_sema.go). Count the Ms
			// from the runtime's thread count, which sees a new M even when no
			// new thread handle or thread ID is visible, and from the
			// timer/packet pair itself, which also sees an extra M whose
			// thread handle dropm closes again. Attribute at most one M's set
			// per M; any other handle, and any excess over that set, is a leak.
			runtimeMs := 0
			if afterRuntimeThreads > beforeRuntimeThreads {
				runtimeMs = int(afterRuntimeThreads - beforeRuntimeThreads)
			}
			liveThreads := newLiveThreads(t, before, after)
			threadIDs := newThreadIDs(beforeThreads, processThreads(t))
			timerMs := min(kinds["IRTimer"]/2, kinds["WaitCompletionPacket"])
			ms := max(runtimeMs, liveThreads, threadIDs, timerMs)
			for _, attributable := range []struct {
				kind string
				per  int
			}{{"Event", 2}, {"IRTimer", 2}, {"WaitCompletionPacket", 1}} {
				if n := min(kinds[attributable.kind], attributable.per*ms); n != 0 {
					kinds[attributable.kind] -= n
				}
			}
			if ms != 0 {
				t.Logf("attributed one runtime M's handles to %d M(s) (runtime threads=%d handle=%d id=%d timer pair=%d) old_pass=false", ms, runtimeMs, liveThreads, threadIDs, timerMs)
			}
			for _, kind := range []string{"Section", "Job", "File", "Pipe", "Process", "Event", "IRTimer", "WaitCompletionPacket", "unreadable"} {
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
