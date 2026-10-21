package localipc

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"testing"
	"time"
)

func TestClientClosesBeforePipeAccept(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Skip("pipe race is exercised on hosted runners")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		t.Skip("the lifecycle SYSTEM harness runs this test with the real pipe server identity")
	}
	path := fmt.Sprintf(`\\.\pipe\netswitch-accept-race-%d`, os.Getpid())
	l, err := Listen(Endpoint{Path: path, Kind: "status"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	name, _ := windows.UTF16PtrFromString(path)
	h, err := windows.CreateFile(name, pipeClientRights, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		t.Fatal(err)
	}
	windows.CloseHandle(h)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := l.Accept(ctx); !errors.Is(err, ErrPeer) {
		t.Fatal("closed client became a fatal listener error", err)
	}
	h, err = windows.CreateFile(name, pipeClientRights, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal("listener not replaced", err)
	}
	defer windows.CloseHandle(h)
	var written uint32
	if err := windows.WriteFile(h, []byte{0}, &written, nil); err != nil || written != 1 {
		t.Fatal("identity handshake", written, err)
	}
	accepted, err := l.Accept(ctx)
	if err != nil {
		t.Fatal("legitimate client after disconnect was refused", err)
	}
	accepted.Close()
}
