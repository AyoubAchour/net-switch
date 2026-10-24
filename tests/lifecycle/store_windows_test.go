package lifecycle_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/lifecycle"
	"github.com/AyoubAchour/net-switch/internal/service"
	"golang.org/x/sys/windows"
)

func heldStoreClient(path string) error {
	if err := os.Mkdir(path, 0700); err != nil {
		return err
	}
	name, _ := windows.UTF16PtrFromString(filepath.Join(path, "held.txt"))
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(h), "held.txt")
	defer f.Close()
	if _, err := f.WriteString("attacker-owned original"); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	fmt.Println("holding untrusted descendant")
	_, err = io.Copy(io.Discard, os.Stdin)
	return err
}

func blockedStoreInstallation(t *testing.T, dir, _ string, other actor) {
	t.Helper()
	logical := filepath.Join(os.Getenv("ProgramData"), fmt.Sprintf("NetSwitch-held-store-%d", os.Getpid()))
	exe, _ := os.Executable()
	attacker := other.command(exe, "client", "held-store", logical)
	in, err := attacker.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := attacker.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := attacker.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { in.Close(); _ = attacker.Wait(); _ = os.RemoveAll(logical) }()
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil || line != "holding untrusted descendant\n" {
		t.Fatal("hostile handle precondition", line, err)
	}
	ctl := filepath.Join(dir, "netswitchctl.exe")
	if b, err := exec.Command(ctl, "install", "--directory", dir, "--data", logical, "--mode", "tun").CombinedOutput(); err != nil {
		t.Fatal("held occupant blocked install", err, string(b))
	}
	physical, err := lifecycle.ResolveStore(logical)
	if err != nil || physical == logical {
		t.Fatal("no protected store indirection", physical, err)
	}
	defer os.RemoveAll(physical)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	defer func() {
		if err := service.Uninstall(ctx); err != nil {
			t.Error(err)
		}
	}()
	for range 2 {
		if _, err := lifecycle.LoadConfig(logical); err != nil {
			t.Fatal(err)
		}
		if err := service.Start(ctx, service.Control); err != nil {
			t.Fatal("start using recorded store", err)
		}
		if err := service.Stop(ctx, service.Control); err != nil {
			t.Fatal(err)
		}
	}
	child := filepath.Join(physical, "parent-acl-case")
	if err := lifecycle.PrepareDirectory(child); err != nil {
		t.Fatal(err)
	}
	restore := writableInstallPath(t, physical)
	parentErr := lifecycle.CheckDirectory(child)
	restore()
	if parentErr == nil {
		t.Fatal("writable --data parent was accepted")
	}
	if err := lifecycle.CheckDirectory(child); err != nil {
		t.Fatal("trusted parent control failed", err)
	}
	b, err := os.ReadFile(filepath.Join(logical, "held.txt"))
	if err != nil || string(b) != "attacker-owned original" {
		t.Fatal("hostile original was modified", err)
	}
	t.Log("held hostile descendant remained open across install and two real Control starts; protected HKLM location verified each time")
}
