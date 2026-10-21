//go:build windows

package wintun

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

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

// Exercise real suspended/running children and pipe reads. Each injected close
// first closes its actual owned handle successfully, then reports an error:
// the caller must propagate that error and must never retry the consumed owner.
func TestWintunRegistrarStartupCloseErrors(t *testing.T) {
	for _, tc := range []struct {
		name, site, fault string
		threadError       bool
	}{
		{"inherited and thread", "Wintun registrar inherited duplicate close", "", true},
		{"parent pipe and thread", "Wintun registrar control read close", "", true},
		{"ready reply", "Wintun registrar reply read close", "", false},
		{"timeout reply", "Wintun registrar reply read close", "hang", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
			kinds := newHandleKinds(t, before, handleSnapshot(t))
			for _, kind := range []string{"Section", "Job", "File", "Pipe", "Process", "Event", "unreadable"} {
				if kinds[kind] != 0 {
					t.Fatalf("startup close failure leaked handles: %v", kinds)
				}
			}
		})
	}
}
