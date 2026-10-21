package localipc

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"runtime"
	"testing"
	"time"
	"unsafe"
)

func TestPipeIdentityUsesEffectiveClientToken(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Skip("hosted SYSTEM pipe probe only")
	}
	primary, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if !primary.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		t.Skip("SYSTEM harness owns the impersonation probe")
	}
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		t.Fatal(err)
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	var source windows.Token
	for _, s := range unsafe.Slice(sessions, count) {
		if s.SessionID != 0 && windows.WTSQueryUserToken(s.SessionID, &source) == nil {
			break
		}
	}
	if source == 0 {
		t.Skip("no real WTS user token available")
	}
	defer source.Close()
	user, err := source.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	var impersonation windows.Token
	if err := windows.DuplicateTokenEx(source, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &impersonation); err != nil {
		t.Fatal(err)
	}
	defer impersonation.Close()
	path := fmt.Sprintf(`\\.\pipe\netswitch-effective-token-%d`, os.Getpid())
	l, err := Listen(Endpoint{Path: path, Kind: "status"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	clientResult := make(chan error, 1)
	var client windows.Handle
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := windows.SetThreadToken(nil, impersonation); err != nil {
			clientResult <- err
			return
		}
		name, _ := windows.UTF16PtrFromString(path)
		h, err := windows.CreateFile(name, pipeClientRights, 0, nil, windows.OPEN_EXISTING, windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == nil {
			client = h
			var n uint32
			err = windows.WriteFile(h, []byte{0}, &n, nil)
		}
		if revert := windows.RevertToSelf(); revert != nil {
			os.Exit(3)
		}
		clientResult <- err
	}()
	if err := <-clientResult; err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(client)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := l.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn.Peer.User != user.User.Sid.String() || conn.Peer.PID != uint32(os.Getpid()) {
		t.Fatal("pipe used primary process identity instead of effective client token", conn.Peer)
	}
}

func TestTCPProcessMustPredateConnection(t *testing.T) {
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &created, &exited, &kernel, &user); err != nil {
		t.Fatal(err)
	}
	at := uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
	if _, err := processPeerAt(uint32(os.Getpid()), at-1); err == nil {
		t.Fatal("reused process identity accepted")
	}
	if _, err := processPeerAt(uint32(os.Getpid()), at); err != nil {
		t.Fatal("same-tick legitimate identity refused", err)
	}
}
