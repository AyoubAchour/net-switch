//go:build windows

package winlock

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func hosted(t *testing.T) {
	t.Helper()
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Skip("native locks are exercised only on disposable hosted CI")
	}
}

func open(t *testing.T, path string) windows.Handle {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_ALWAYS, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestContentionCancellationAndRelease(t *testing.T) {
	hosted(t)
	path := filepath.Join(t.TempDir(), "lock")
	first, second := open(t, path), open(t, path)
	defer windows.CloseHandle(second)
	if err := Acquire(context.Background(), first); err != nil {
		windows.CloseHandle(first)
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	err := Acquire(ctx, second)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		windows.CloseHandle(first)
		t.Fatalf("contender bypassed byte lock: %v", err)
	}
	if err := windows.CloseHandle(first); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := Acquire(ctx, second); err != nil {
		t.Fatalf("closing owner did not release lock: %v", err)
	}
	t.Log("second open was excluded while owner held byte zero; cancellation returned; close released it")
}

func TestLockChild(t *testing.T) {
	hosted(t)
	path := os.Getenv("NETSWITCH_LOCK_CHILD")
	if path == "" {
		t.Skip("child process only")
	}
	h := open(t, path)
	defer windows.CloseHandle(h)
	if err := Acquire(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	fmt.Println("LOCK HELD")
	io.Copy(io.Discard, os.Stdin)
}

func TestProcessDeathReleasesLock(t *testing.T) {
	hosted(t)
	path := filepath.Join(t.TempDir(), "lock")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, executable, "-test.run=^TestLockChild$")
	child.Env = append(os.Environ(), "NETSWITCH_LOCK_CHILD="+path)
	input, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer child.Process.Kill()
	if line, err := bufio.NewReader(output).ReadString('\n'); err != nil || line != "LOCK HELD\n" {
		t.Fatalf("child precondition: %q %v", line, err)
	}
	contender := open(t, path)
	defer windows.CloseHandle(contender)
	short, stop := context.WithTimeout(ctx, 100*time.Millisecond)
	err = Acquire(short, contender)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("live child did not own the lock: %v", err)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	child.Wait()
	if err := Acquire(ctx, contender); err != nil {
		t.Fatalf("dead process retained lock: %v", err)
	}
	t.Log("child ownership positively observed before kill; same contender acquired after process death")
}
