//go:build windows

package winengine

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

const oldOwnershipMutex = `Global\NetSwitchEngineOwnership-` + wintunMutexID

func ownershipSquatter() error {
	if err := mediumPeerIdentity(); err != nil {
		return err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	name, _ := windows.UTF16PtrFromString(oldOwnershipMutex)
	h, err := windows.CreateMutex(nil, true, name)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	defer windows.ReleaseMutex(h)
	fmt.Println("MEDIUM SQUATTER HOLDS GLOBAL MUTEX")
	_, err = io.Copy(io.Discard, os.Stdin)
	return err
}

func TestOwnershipLockIgnoresGlobalSquatter(t *testing.T) {
	hosted(t)
	token := restrictedPeerToken(t)
	defer token.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, executable)
	child.Env = append(os.Environ(), "NETSWITCH_OWNERSHIP_SQUATTER=1")
	child.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(token), CreationFlags: windows.DETACHED_PROCESS, HideWindow: true}
	input, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { child.Process.Kill(); child.Wait() }()
	line, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || line != "MEDIUM SQUATTER HOLDS GLOBAL MUTEX\n" {
		t.Fatalf("squatter precondition: %q %v", line, err)
	}
	name, _ := windows.UTF16PtrFromString(oldOwnershipMutex)
	squatted, err := windows.OpenMutex(windows.SYNCHRONIZE, false, name)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(squatted)
	if result, err := windows.WaitForSingleObject(squatted, 0); err != nil || result != uint32(windows.WAIT_TIMEOUT) {
		t.Fatalf("old mutex was not held: result=%d err=%v", result, err)
	}
	unlock, err := (OwnershipLock{}).Acquire(ctx)
	if err != nil {
		t.Fatalf("live squatter prevented engine ownership: %v", err)
	}
	defer unlock()
	short, stop := context.WithTimeout(ctx, 100*time.Millisecond)
	second, err := (OwnershipLock{}).Acquire(short)
	stop()
	if second != nil {
		second()
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("legitimate second owner bypassed exclusion: %v", err)
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	again, err := (OwnershipLock{}).Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := again(); err != nil {
		t.Fatal(err)
	}
	if result, err := windows.WaitForSingleObject(squatted, 0); err != nil || result != uint32(windows.WAIT_TIMEOUT) {
		t.Fatalf("squatter must remain active throughout test: %d %v", result, err)
	}
	t.Log("verified Medium deny-only squatter held old Global mutex throughout; engine acquired, excluded second owner, released and reacquired")
}
