//go:build windows

package winengine

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	winplatform "github.com/AyoubAchour/net-switch/internal/platform/windows"
	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const ownershipFixtureEnv = "NETSWITCH_OWNERSHIP_DIRECTORY_FIXTURE"

func ownershipTestPath() (string, error) {
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	return filepath.Join(root, "Net Switch Engine Ownership"), err
}

func ownershipDirectoryFixture(mode string) error {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		return errors.New("ownership fixtures are hosted CI only")
	}
	path, err := ownershipTestPath()
	if err != nil {
		return err
	}
	if strings.HasPrefix(mode, "squat-") {
		return holdHostileOwnershipDirectory(path, mode == "squat-dacl")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	switch mode {
	case "prepare":
		return withOwnershipPreparation(ctx, func() error {
			fmt.Println("PREPARING")
			_, err := io.Copy(io.Discard, os.Stdin)
			return err
		})
	case "lock":
		fmt.Println("READY")
		var goByte [1]byte
		if _, err := io.ReadFull(os.Stdin, goByte[:]); err != nil {
			return err
		}
		unlock, err := (OwnershipLock{}).Acquire(ctx)
		if err != nil {
			return err
		}
		defer unlock()
		resolved, err := winplatform.ResolveMachineDirectory(path)
		if err != nil {
			return err
		}
		fmt.Println("LOCKED " + resolved)
		_, err = io.Copy(io.Discard, os.Stdin)
		return err
	case "serve":
		return Serve(ctx, os.Getenv("NETSWITCH_OWNERSHIP_STATE"), true)
	case "recover":
		return Recover(os.Getenv("NETSWITCH_OWNERSHIP_STATE"))
	default:
		return fmt.Errorf("unknown ownership fixture %q", mode)
	}
}

func holdHostileOwnershipDirectory(path string, denyRead bool) error {
	if err := mediumPeerIdentity(); err != nil {
		return err
	}
	// Check before any administrator creates the namespace, and again on
	// every held-handle probe after legitimate startup has created it.
	deniedNamespace := func() error {
		_, err := openOwnershipNamespace()
		if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return fmt.Errorf("Medium peer was not denied preparation namespace: %v", err)
		}
		return nil
	}
	if err := deniedNamespace(); err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sa, err := security("O:" + user.User.Sid.String() + "D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)")
	if err != nil {
		return err
	}
	p, _ := windows.UTF16PtrFromString(path)
	if err := windows.CreateDirectory(p, sa); err != nil {
		return fmt.Errorf("create hostile ownership folder: %w", err)
	}
	h, err := windows.CreateFile(p, windows.FILE_LIST_DIRECTORY|windows.READ_CONTROL|windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return err
	}
	owner := winhandle.Open(h, "hostile ownership directory open")
	defer owner.HandleClose("hostile ownership directory close")
	if denyRead {
		dacl, _, err := sa.SecurityDescriptor.DACL()
		if err != nil {
			return err
		}
		defer windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
		empty, err := windows.SecurityDescriptorFromString("D:P")
		if err != nil {
			return err
		}
		blocked, _, err := empty.DACL()
		if err != nil {
			return err
		}
		if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, blocked, nil); err != nil {
			return err
		}
	}
	probe := func() error {
		if err := deniedNamespace(); err != nil {
			return err
		}
		var info windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(owner.Handle("hostile ownership still held"), &info); err != nil {
			return err
		}
		fmt.Printf("HELD %08x:%08x%08x\n", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow)
		return nil
	}
	if err := probe(); err != nil {
		return err
	}
	var b [1]byte
	for {
		if _, err := os.Stdin.Read(b[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := probe(); err != nil {
			return err
		}
	}
}

type ownershipChild struct {
	cmd   *exec.Cmd
	input io.WriteCloser
	lines chan string
	done  chan struct{}
	err   error
	stop  func()
}

func startOwnershipChild(t *testing.T, mode, state string, token windows.Token) *ownershipChild {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	child := &ownershipChild{cmd: exec.CommandContext(ctx, self), lines: make(chan string, 64), done: make(chan struct{})}
	child.cmd.Env = append(os.Environ(), ownershipFixtureEnv+"="+mode, "NETSWITCH_OWNERSHIP_STATE="+state)
	if token != 0 {
		child.cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(token), CreationFlags: windows.DETACHED_PROCESS, HideWindow: true}
	}
	child.input, err = child.cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	output, err := child.cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	child.cmd.Stderr = os.Stderr
	if err := child.cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	scanned := make(chan struct{})
	go func() {
		defer close(scanned)
		defer close(child.lines)
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			child.lines <- scanner.Text()
		}
	}()
	go func() {
		<-scanned
		child.err = child.cmd.Wait()
		close(child.done)
	}()
	child.stop = sync.OnceFunc(func() {
		child.input.Close()
		select {
		case <-child.done:
		case <-time.After(5 * time.Second):
			child.cmd.Process.Kill()
			<-child.done
		}
		cancel()
	})
	t.Cleanup(child.stop)
	return child
}

func (c *ownershipChild) line(t *testing.T, prefix string) string {
	t.Helper()
	timeout := time.NewTimer(15 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case line, ok := <-c.lines:
			if !ok {
				<-c.done
				t.Fatalf("ownership child ended before %s: %v", prefix, c.err)
			}
			if strings.HasPrefix(line, prefix) {
				return line
			}
			t.Log(line)
		case <-timeout.C:
			t.Fatalf("ownership child did not report %s", prefix)
		}
	}
}

func (c *ownershipChild) kill(t *testing.T) {
	t.Helper()
	if err := c.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		t.Fatal("ownership child did not exit after termination")
	}
}

func ownershipHello(t *testing.T, child *ownershipChild) {
	t.Helper()
	ptr, _ := windows.UTF16PtrFromString(EnginePipe)
	deadline := time.Now().Add(15 * time.Second)
	for {
		h, err := windows.CreateFile(ptr, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
		if err == nil {
			client := winhandle.NewFile(winhandle.Open(h, "ownership startup hello open"), EnginePipe)
			defer client.Close()
			if err := client.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if err := json.NewEncoder(client).Encode(protocol.Request{ID: "ownership-startup", Method: "hello"}); err != nil {
				t.Fatal(err)
			}
			var reply protocol.Reply
			if err := json.NewDecoder(client).Decode(&reply); err != nil || reply.Error != "" || reply.ID != "ownership-startup" {
				t.Fatalf("real engine startup hello: %+v %v", reply, err)
			}
			return
		}
		if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(err, windows.ERROR_PIPE_BUSY) {
			t.Fatal(err)
		}
		select {
		case <-child.done:
			t.Fatalf("engine exited before startup hello: %v", child.err)
		case <-time.After(25 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("engine did not become ready")
		}
	}
}

func TestOwnershipLockHostileDirectoryStartupAndRecovery(t *testing.T) {
	hosted(t)
	if os.Getenv("NETSWITCH_OWNERSHIP_DIRECTORY_CI") != "1" {
		t.Skip("dedicated fresh-runner ownership regression")
	}
	if !Elevated() {
		t.Fatal("ownership regression requires an elevated hosted runner")
	}
	for _, mode := range []string{"squat-handle", "squat-dacl"} {
		t.Run(mode, func(t *testing.T) {
			path, err := ownershipTestPath()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("fresh-runner precondition: default already exists: %v", err)
			}
			resolved, err := winplatform.ResolveMachineDirectory(path)
			if err != nil || !strings.EqualFold(resolved, path) {
				t.Fatalf("fresh-runner precondition: existing location record %q %v", resolved, err)
			}
			t.Cleanup(func() { cleanupOwnershipFixture(t, path) })
			token := restrictedPeerToken(t)
			defer token.Close()
			blocker := startOwnershipChild(t, mode, "", windows.Token(token.owner.Handle("hostile folder creator launch")))
			held := blocker.line(t, "HELD ")
			assertHeld := func() {
				t.Helper()
				if _, err := blocker.input.Write([]byte("?")); err != nil {
					t.Fatal(err)
				}
				if got := blocker.line(t, "HELD "); got != held {
					t.Fatalf("hostile folder/handle changed: %q -> %q", held, got)
				}
			}
			// Exercise the exact old boundary before crediting a fallback. In
			// the DACL variant inspection fails; in the other, rename fails.
			old, oldErr := StateDirectory(path)
			if old != nil {
				old.Close()
			}
			want := error(windows.ERROR_SHARING_VIOLATION)
			if mode == "squat-dacl" {
				want = windows.ERROR_ACCESS_DENIED
			}
			if !errors.Is(oldErr, want) {
				t.Fatalf("old ownership path did not reproduce %v: %v", want, oldErr)
			}
			assertHeld()
			t.Logf("old path reproduced %v while %s", oldErr, held)

			// Terminate the process that created the preparation namespace
			// while two first starts are waiting in it. This covers abandoned
			// mutexes as well as publication by overlapping initializers.
			initializer := startOwnershipChild(t, "prepare", "", 0)
			initializer.line(t, "PREPARING")
			first := startOwnershipChild(t, "lock", "", 0)
			second := startOwnershipChild(t, "lock", "", 0)
			first.line(t, "READY")
			second.line(t, "READY")
			first.input.Write([]byte("!"))
			second.input.Write([]byte("!"))
			// A real acquisition cannot pass the still-held preparation guard.
			for _, child := range []*ownershipChild{first, second} {
				select {
				case line := <-child.lines:
					t.Fatalf("preparation guard did not exclude contender: %q", line)
				case <-time.After(150 * time.Millisecond):
				}
			}
			initializer.kill(t)
			type acquired struct {
				child *ownershipChild
				line  string
			}
			owners := make(chan acquired, 2)
			for _, child := range []*ownershipChild{first, second} {
				go func() {
					for line := range child.lines {
						if strings.HasPrefix(line, "LOCKED ") {
							owners <- acquired{child, line}
							return
						}
					}
					owners <- acquired{child, "child exited before ownership"}
				}()
			}
			awaitOwner := func() acquired {
				t.Helper()
				select {
				case owner := <-owners:
					if !strings.HasPrefix(owner.line, "LOCKED ") {
						t.Fatal(owner.line)
					}
					return owner
				case <-time.After(15 * time.Second):
					t.Fatal("no engine acquired ownership after initializer crash")
					return acquired{}
				}
			}
			winner := awaitOwner()
			resolved = strings.TrimPrefix(winner.line, "LOCKED ")
			if strings.EqualFold(path, resolved) || !strings.HasPrefix(strings.ToLower(resolved), strings.ToLower(path)+".store-") {
				t.Fatalf("hostile default was not bypassed: %q", resolved)
			}
			select {
			case other := <-owners:
				t.Fatalf("second engine bypassed lifetime lock: %s", other.line)
			case <-time.After(250 * time.Millisecond):
			}
			assertHeld()
			winner.child.kill(t)
			next := awaitOwner()
			if next.line != winner.line {
				t.Fatalf("overlapping starts chose different locations: %q / %q", winner.line, next.line)
			}
			next.child.kill(t)

			state := filepath.Join(t.TempDir(), "state")
			engine := startOwnershipChild(t, "serve", state, 0)
			ownershipHello(t, engine)
			assertHeld()
			short, stop := context.WithTimeout(context.Background(), 150*time.Millisecond)
			unlock, err := (OwnershipLock{}).Acquire(short)
			stop()
			if unlock != nil {
				unlock()
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("live certified engine did not exclude another owner: %v", err)
			}
			engine.kill(t)
			recovery := startOwnershipChild(t, "recover", state, 0)
			select {
			case <-recovery.done:
				if recovery.err != nil {
					t.Fatal("recovery failed with blocker held", recovery.err)
				}
			case <-time.After(15 * time.Second):
				t.Fatal("recovery blocked by hostile folder")
			}
			assertHeld()
			again := startOwnershipChild(t, "serve", state, 0)
			ownershipHello(t, again)
			assertHeld()
			if got, err := winplatform.ResolveMachineDirectory(path); err != nil || got != resolved {
				t.Fatalf("startup/recovery changed authoritative location: %q %v", got, err)
			}
			again.kill(t)
			t.Logf("Medium blocker held %s throughout: two simultaneous owners serialized at %s; real Serve hello, crash, Recover and restarted Serve succeeded; live owner excluded a second acquisition", held, resolved)
		})
	}
}

func cleanupOwnershipFixture(t *testing.T, path string) {
	t.Helper()
	// Children stop first (LIFO Cleanup). Only remove the exact fixture root
	// and its fresh siblings on this disposable hosted runner.
	names, err := filepath.Glob(path + ".*")
	if err != nil {
		t.Error(err)
		return
	}
	names = append(names, path)
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\NetSwitch.ControlDirectoryCertificates.v1`, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		t.Error(err)
		return
	}
	defer key.Close()
	for _, name := range names {
		if filepath.Dir(name) != filepath.Dir(path) || (name != path && !strings.HasPrefix(name, path+".store-") && !strings.HasPrefix(name, path+".untrusted-") && name != path+".migrating") {
			t.Errorf("refusing unrelated fixture cleanup %q", name)
			continue
		}
		if err := os.RemoveAll(name); err != nil {
			t.Error(err)
		}
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(strings.ToLower(name))))
		for _, value := range []string{hash, "store-" + hash} {
			if err := key.DeleteValue(value); err != nil && !errors.Is(err, registry.ErrNotExist) {
				t.Error(err)
			}
		}
	}
}
