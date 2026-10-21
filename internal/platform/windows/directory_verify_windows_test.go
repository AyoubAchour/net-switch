package winplatform

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestVerifyMachineStoreWithLiveEngineDirectory(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Skip("native store protection is hosted-only")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("machine-store verification test requires elevation")
	}
	// A machine store's ancestors must have installation-grade ACLs. The
	// runner's per-user Temp tree deliberately does not meet that condition.
	path := filepath.Join(os.Getenv("ProgramData"), fmt.Sprintf("NetSwitch-live-store-%d", time.Now().UnixNano()))
	t.Cleanup(func() {
		if err := os.RemoveAll(path); err != nil {
			t.Error(err)
		}
	})
	if err := ProtectDirectory(path); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(path, "active-engine")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(path, directoryMarkerName)
	before, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	name, _ := windows.UTF16PtrFromString(child)
	// Hold a directory read handle without delete sharing. Metadata-only
	// access does not participate in sharing checks, so it cannot establish
	// the live-directory conflict that this test must prove first.
	held, err := windows.CreateFile(name, windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(held)
	mutable, err := windows.CreateFile(name, windows.DELETE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err == nil {
		windows.CloseHandle(mutable)
		t.Fatal("test did not establish the live-directory sharing restriction")
	}
	if err != windows.ERROR_SHARING_VIOLATION {
		t.Fatal("wrong precondition failure", err)
	}
	if err := VerifyDirectory(path); err != nil {
		t.Fatal("live engine prevented read-only verification", err)
	}
	after, err := os.ReadFile(markerPath)
	if err != nil || string(before) != string(after) {
		t.Fatal("verification rewrote the installation identity", err)
	}
}
