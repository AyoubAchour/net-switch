//go:build windows && netswitch_handlecheck

package winengine

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

func TestHeapCaptureIsFreshAndEventRejectsMediumToken(t *testing.T) {
	hosted(t)
	t.Setenv("NETSWITCH_ENGINE_TEST_TRACE", "1")
	const nonce = "6fc31ffba4454528b36d114185a55102"
	const requestNonce = "788318a5ea444ba992adfdfd2052b126"
	dir := filepath.Join(t.TempDir(), "private-heap")
	p, err := openHeapProfile(dir, nonce, "heap-fixture")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.close(); err != nil {
			t.Error(err)
		}
	})
	// The live event exists before the negative control. Request exactly the
	// same EVENT_MODIFY_STATE access as the legitimate harness helper.
	if state, err := windows.WaitForSingleObject(p.request.Handle("heap ACL probe precondition"), 0); err != nil || state != uint32(windows.WAIT_TIMEOUT) {
		t.Fatalf("fresh heap request event was not present and unsignalled: %d %v", state, err)
	}
	token := restrictedPeerToken(t)
	defer token.Close()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(self)
	child.Env = append(os.Environ(), "NETSWITCH_HEAP_EVENT_DENIED="+p.info.Event)
	child.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(token.owner.Handle("heap negative peer launch")),
		CreationFlags: windows.DETACHED_PROCESS, HideWindow: true}
	output, err := child.CombinedOutput()
	t.Logf("%s", output)
	if err != nil {
		t.Fatal(err)
	}
	result, err := requestHeapCapture(dir, nonce, "heap-fixture", requestNonce, "held", os.Getpid(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if result.HeapAlloc == 0 || result.ForcedGCAfter <= result.ForcedGCBefore ||
		result.Request.RequestNonce != requestNonce || result.KernelSocketBytes != nil || result.KernelSocketMemoryNote == "" {
		t.Fatalf("capture was not fresh or claimed unknown kernel memory as zero: %+v", result)
	}
	if _, err := requestHeapCapture(dir, nonce, "wrong-instance", requestNonce, "held", os.Getpid(), 2); err == nil {
		t.Fatal("different engine instance accepted")
	}
	if _, err := requestHeapCapture(dir, nonce, "heap-fixture", requestNonce, "held", os.Getpid(), 1); err == nil {
		t.Fatal("duplicate sequence accepted")
	}
	// A ready-looking stale result must not count as this request's capture.
	if err := publishHeapJSON(filepath.Join(dir, "memory-000002.json"), result); err != nil {
		t.Fatal(err)
	}
	_, err = requestHeapCapture(dir, nonce, "heap-fixture", "582d89817f4e4db48b0a938de8124607", "second", os.Getpid(), 2)
	if err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale completion accepted: %v", err)
	}
	t.Logf("fresh forced GC %d -> %d, heap=%d; medium event access, wrong instance, duplicate sequence and stale completion rejected",
		result.ForcedGCBefore, result.ForcedGCAfter, result.HeapAlloc)
}

func TestHeapEventNeverAdoptsAnExistingName(t *testing.T) {
	hosted(t)
	const name = `Local\NetSwitchEngineHeap-collision-fixture`
	first, err := createHeapEvent(name)
	if err != nil {
		t.Fatal(err)
	}
	defer first.HandleClose("heap event collision fixture close")
	if _, err := createHeapEvent(name); err == nil {
		t.Fatal("an existing event's ACL was silently adopted")
	}
	if err := windows.SetEvent(first.Handle("heap collision survivor")); err != nil {
		t.Fatal(err)
	}
}

func deniedHeapEventClient(name string) error {
	if err := mediumPeerIdentity(); err != nil {
		return err
	}
	ptr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	h, err := windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, ptr)
	if err == nil {
		winhandle.Open(h, "heap negative peer unexpectedly opened").HandleClose("heap negative peer close")
		return errors.New("medium peer opened the heap request event")
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return err
	}
	return nil
}
