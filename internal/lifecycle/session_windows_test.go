package lifecycle

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"testing"
	"unsafe"
)

func TestRealWindowsOwnerSession(t *testing.T) {
	if os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("NETSWITCH_REAL_WTS_PROBE") != "1" {
		t.Skip("hosted SYSTEM WTS probe only")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		t.Fatal("hosted real WTS probe must run under SYSTEM")
	}
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		t.Fatal(err)
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	for _, s := range unsafe.Slice(sessions, count) {
		if s.SessionID == 0 {
			continue
		}
		var token windows.Token
		if err := windows.WTSQueryUserToken(s.SessionID, &token); err != nil {
			if errors.Is(err, windows.ERROR_NO_TOKEN) {
				continue
			}
			t.Fatalf("WTS token for session %d: %v", s.SessionID, err)
		}
		user, err := token.GetTokenUser()
		token.Close()
		if err != nil {
			t.Fatal(err)
		}
		present, err := ownerSessionPresent(user.User.Sid.String(), ^uint32(0))
		if err != nil || !present {
			t.Fatal("real WTS owner was not found", err)
		}
		t.Logf("real WTS owner matched in session %d", s.SessionID)
		t.Logf("REAL_WTS_OWNER=%s", user.User.Sid.String())
		return
	}
	t.Skip("hosted runner has no real signed-in WTS user; synthetic session events are tested separately")
}
