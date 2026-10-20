//go:build windows

package winengine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestMain(m *testing.M) {
	if os.Getenv("NETSWITCH_PIPE_DENIED_CHILD") == "1" {
		if err := deniedPipeClient(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func deniedPipeClient() error {
	token := windows.GetCurrentProcessToken()
	if token.IsElevated() {
		return errors.New("negative peer was still elevated")
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return err
	}
	denyOnly := false
	for _, group := range groups.AllGroups() {
		if group.Sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			denyOnly = group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY != 0 && group.Attributes&windows.SE_GROUP_ENABLED == 0
		}
	}
	if !denyOnly {
		return errors.New("negative peer still has enabled Administrators membership")
	}
	var length uint32
	windows.GetTokenInformation(token, windows.TokenIntegrityLevel, nil, 0, &length)
	b := make([]byte, length)
	if err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel, &b[0], length, &length); err != nil {
		return err
	}
	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&b[0]))
	if label.Label.Sid.String() != "S-1-16-8192" {
		return fmt.Errorf("negative peer integrity is %s", label.Label.Sid.String())
	}
	p, _ := windows.UTF16PtrFromString(EnginePipe)
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if err == nil {
		windows.CloseHandle(h)
		return errors.New("medium deny-only peer opened the engine pipe")
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return fmt.Errorf("unexpected negative-peer error: %w", err)
	}
	fmt.Println("Medium integrity, Administrators deny-only, not elevated: engine pipe denied access")
	return nil
}

func restrictedPeerToken(t *testing.T) windows.Token {
	t.Helper()
	var original windows.Token
	// CreateRestrictedToken preserves the handle's access rights. The fixture
	// needs ADJUST_DEFAULT to lower integrity before starting the negative peer.
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_ADJUST_DEFAULT, &original); err != nil {
		t.Fatalf("open parent token: %v", err)
	}
	defer original.Close()
	admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	disabled := windows.SIDAndAttributes{Sid: admin}
	var token windows.Token
	ok, _, err := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken").Call(
		uintptr(original), 1, 1, uintptr(unsafe.Pointer(&disabled)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&token)))
	if ok == 0 {
		t.Fatalf("create restricted peer token: %v", err)
	}
	medium, err := windows.StringToSid("S-1-16-8192")
	if err != nil {
		token.Close()
		t.Fatal(err)
	}
	label := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: medium, Attributes: windows.SE_GROUP_INTEGRITY}}
	if err := windows.SetTokenInformation(token, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&label)), uint32(unsafe.Sizeof(label))+uint32(medium.Len())); err != nil {
		token.Close()
		t.Fatalf("lower peer integrity to Medium: %v", err)
	}
	return token
}

func TestEnginePipeAuthenticatesRealTokens(t *testing.T) {
	hosted(t)
	listener, err := ListenPipe(EnginePipe, true)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	token := restrictedPeerToken(t)
	defer token.Close()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(self)
	child.Env = append(os.Environ(), "NETSWITCH_PIPE_DENIED_CHILD=1")
	child.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(token), CreationFlags: windows.DETACHED_PROCESS, HideWindow: true}
	output, err := child.CombinedOutput()
	t.Logf("%s", output)
	if err != nil {
		t.Fatal(err)
	}
	// The negative control must not prevent the legitimate elevated peer
	// from exchanging data and receiving the final write before close.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		var b [4]byte
		_, err = io.ReadFull(conn, b[:])
		if err == nil && string(b[:]) != "ping" {
			err = errors.New("wrong pipe request")
		}
		if err == nil {
			_, err = conn.Write([]byte("pong"))
		}
		done <- err
	}()
	ptr, _ := windows.UTF16PtrFromString(EnginePipe)
	h, err := windows.CreateFile(ptr, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		t.Fatal(err)
	}
	client := os.NewFile(uintptr(h), EnginePipe)
	defer client.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var b [4]byte
	if _, err := io.ReadFull(client, b[:]); err != nil || string(b[:]) != "pong" {
		t.Fatalf("%q %v", b[:], err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestServiceEnginePipeRejectsAdministrator(t *testing.T) {
	hosted(t)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		t.Skip("this negative control requires the hosted administrator identity")
	}
	listener, err := ListenPipe(EnginePipe, false)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ptr, _ := windows.UTF16PtrFromString(EnginePipe)
	h, err := windows.CreateFile(ptr, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if err == nil {
		windows.CloseHandle(h)
		t.Fatal("administrator opened the SYSTEM-only service pipe")
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatal(err)
	}
}

func TestPipeCloseWakesAccept(t *testing.T) {
	hosted(t)
	for range 32 {
		p, err := ListenPipe(EnginePipe, true)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, err := p.Accept(context.Background()); done <- err }()
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("closed listener accepted a peer")
			}
		case <-time.After(time.Second):
			t.Fatal("close did not cancel pending accept")
		}
	}
}
