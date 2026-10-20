package winplatform

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestStorePublicationInterruptionWithHeldHostileOccupant(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Skip("hosted machine-store test only")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("store test must be elevated")
	}
	root := filepath.Join(os.Getenv("ProgramData"), fmt.Sprintf("NetSwitch-publish-%d", time.Now().UnixNano()))
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	path, _ := windows.UTF16PtrFromString(filepath.Join(root, "held"))
	h, err := windows.CreateFile(path, windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	interrupted := errors.New("interrupted before location publication")
	first := ""
	_, err = prepareMachineDirectory(root, func(fresh string) error {
		first = fresh
		if err := VerifyDirectory(fresh); err != nil {
			t.Fatal(err)
		}
		return interrupted
	})
	if !errors.Is(err, interrupted) || first == "" {
		t.Fatal("interruption barrier not reached", err)
	}
	defer os.RemoveAll(first)
	resolved, err := ResolveMachineDirectory(root)
	if err != nil || resolved != root {
		t.Fatal("unpublished store became visible", resolved, err)
	}
	second, err := PrepareMachineDirectory(root)
	if err != nil || second == root {
		t.Fatal("retry remained locked out by the hostile handle", second, err)
	}
	defer os.RemoveAll(second)
	resolved, err = ResolveMachineDirectory(root)
	if err != nil || resolved != second {
		t.Fatal("published store did not survive reread", resolved, err)
	}
}
