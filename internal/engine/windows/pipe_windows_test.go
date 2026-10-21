//go:build windows

package winengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
	"unsafe"

	winplatform "github.com/AyoubAchour/net-switch/internal/platform/windows"
	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

func TestMain(m *testing.M) {
	if os.Getenv("NETSWITCH_EXPECT_HANDLECHECK") == "1" && !winhandle.Enabled {
		fmt.Fprintln(os.Stderr, "CI required netswitch_handlecheck but it was not compiled")
		os.Exit(1)
	}
	if name := os.Getenv("NETSWITCH_HEAP_EVENT_DENIED"); name != "" {
		if err := deniedHeapEventClient(name); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("Medium integrity, Administrators deny-only: heap event denied EVENT_MODIFY_STATE")
		os.Exit(0)
	}
	if len(os.Args) == 4 && os.Args[1] == "worker" && os.Args[2] == "query" && os.Args[3] == "tcp-port-configuration" {
		os.Exit(winplatform.Run(os.Args[2:]))
	}
	if os.Getenv("NETSWITCH_OWNERSHIP_SQUATTER") == "1" {
		if err := ownershipSquatter(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if os.Getenv(pipeOSFileDuplexEnv) == "1" {
		if err := osFileDuplexChild(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("os.File duplex control exchanged 1 MiB each way")
		os.Exit(0)
	}
	if os.Getenv("NETSWITCH_PIPE_DENIED_CHILD") == "1" {
		if err := deniedPipeClient(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	result := m.Run()
	if winhandle.Enabled {
		value, _ := json.Marshal(winhandle.Stats())
		fmt.Printf("WINDOWS HANDLE OWNERSHIP %s\n", value)
	}
	os.Exit(result)
}

func mediumPeerIdentity() error {
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
	return nil
}

func deniedPipeClient() error {
	if err := mediumPeerIdentity(); err != nil {
		return err
	}
	p, _ := windows.UTF16PtrFromString(EnginePipe)
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if err == nil {
		winhandle.Open(h, "denied pipe probe unexpectedly opened").HandleClose("denied pipe probe close")
		return errors.New("medium deny-only peer opened the engine pipe")
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return fmt.Errorf("unexpected negative-peer error: %w", err)
	}
	fmt.Println("Medium integrity, Administrators deny-only, not elevated: engine pipe denied access")
	return nil
}

type peerToken struct {
	windows.Token
	owner winhandle.Owner
}

func (p peerToken) Close() error {
	return p.owner.CloseGo("restricted peer token close", p.Token.Close)
}

func restrictedPeerToken(t *testing.T) peerToken {
	t.Helper()
	var original windows.Token
	// CreateRestrictedToken preserves the handle's access rights. The fixture
	// needs ADJUST_DEFAULT to lower integrity before starting the negative peer.
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_ADJUST_DEFAULT, &original); err != nil {
		t.Fatalf("open parent token: %v", err)
	}
	originalOwner := winhandle.Open(windows.Handle(original), "restricted peer original token open")
	defer originalOwner.CloseGo("restricted peer original token close", original.Close)
	admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	disabled := windows.SIDAndAttributes{Sid: admin}
	var token windows.Token
	ok, _, err := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken").Call(
		uintptr(originalOwner.Handle("restricted peer token duplicate")), 1|4, 1, uintptr(unsafe.Pointer(&disabled)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&token))) // DISABLE_MAX_PRIVILEGE | LUA_TOKEN.
	if ok == 0 {
		t.Fatalf("create restricted peer token: %v", err)
	}
	tokenOwner := winhandle.Open(windows.Handle(token), "restricted peer token open")
	medium, err := windows.StringToSid("S-1-16-8192")
	if err != nil {
		tokenOwner.CloseGo("restricted peer SID failure close", token.Close)
		t.Fatal(err)
	}
	label := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: medium, Attributes: windows.SE_GROUP_INTEGRITY}}
	if err := windows.SetTokenInformation(windows.Token(tokenOwner.Handle("restricted peer integrity")), windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&label)), uint32(unsafe.Sizeof(label))+uint32(medium.Len())); err != nil {
		tokenOwner.CloseGo("restricted peer integrity failure close", token.Close)
		t.Fatalf("lower peer integrity to Medium: %v", err)
	}
	return peerToken{token, tokenOwner}
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
	child.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(token.owner.Handle("restricted pipe peer launch")), CreationFlags: windows.DETACHED_PROCESS, HideWindow: true}
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
	client := winhandle.NewFile(winhandle.Open(h, "legitimate pipe regression open"), EnginePipe)
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
		winhandle.Open(h, "service pipe negative probe unexpectedly opened").HandleClose("service pipe negative probe close")
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

func TestPipeDisconnectedBeforeAcceptIsRetryable(t *testing.T) {
	hosted(t)
	p, err := ListenPipe(EnginePipe, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { p.Close() }()
	name, _ := windows.UTF16PtrFromString(EnginePipe)
	for round := range 32 {
		// Connect and disappear before the server calls ConnectNamedPipe.
		h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
			windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
		if err != nil {
			t.Fatal(err)
		}
		winhandle.Open(h, "early pipe disconnect probe open").HandleClose("early pipe disconnect probe close")
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err = p.Accept(ctx)
		cancel()
		if !errors.Is(err, errPeerRefused) {
			t.Fatalf("early disconnect became fatal: %v", err)
		}
		if round != 31 {
			// Each deterministic pre-Accept case needs a freshly created
			// instance. DisconnectNamedPipe requires ConnectNamedPipe before
			// another client can connect; production calls Accept immediately.
			p.Close()
			p, err = ListenPipe(EnginePipe, true)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		conn, err := p.Accept(ctx)
		if err == nil {
			_, err = conn.Write([]byte("ok"))
			conn.Close()
		}
		done <- err
	}()
	// Re-arm the same last instance, exactly as the production accept loop
	// does. The client waits for listening, not for an arbitrary sleep.
	if ok, _, err := windows.NewLazySystemDLL("kernel32.dll").NewProc("WaitNamedPipeW").Call(uintptr(unsafe.Pointer(name)), 1000); ok == 0 {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		t.Fatal(err)
	}
	client := winhandle.NewFile(winhandle.Open(h, "post-disconnect pipe regression open"), EnginePipe)
	defer client.Close()
	client.SetDeadline(time.Now().Add(time.Second))
	var b [2]byte
	if _, err := io.ReadFull(client, b[:]); err != nil || string(b[:]) != "ok" {
		t.Fatalf("legitimate reply after retry: %q %v", b, err)
	}
	if err := <-done; err != nil {
		t.Fatalf("legitimate peer after early disconnects: %v", err)
	}
	t.Log("32 disconnects before Accept remained retryable; legitimate peer then received its reply")
}
