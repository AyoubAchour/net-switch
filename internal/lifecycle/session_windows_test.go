package lifecycle

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"testing"
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
	t.Logf("WTS sessions: %s", describeSessions())
	sessions, err := wtsSessions()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sessions {
		if !userSession(s) {
			continue
		}
		sid, err := wtsSessionUser(s.id)
		if err != nil {
			if errors.Is(err, windows.ERROR_NO_TOKEN) {
				continue
			}
			t.Fatalf("WTS token for session %d: %v", s.id, err)
		}
		present, err := ownerSessionPresent(sid, ^uint32(0))
		if err != nil || !present {
			t.Fatal("real WTS owner was not found", err)
		}
		t.Logf("real WTS owner matched in session %d", s.id)
		t.Logf("REAL_WTS_OWNER=%s", sid)
		return
	}
	t.Skip("hosted runner has no real signed-in WTS user; synthetic session events are tested separately")
}

func TestWTSOwnerAbsenceSkipsSessionsWithoutUsers(t *testing.T) {
	sessions := []wtsSession{
		{id: 0, state: windows.WTSDisconnected, name: "Services"},
		{id: 1, state: windows.WTSConnected, name: "Console"},
		{id: 2, state: windows.WTSDisconnected},
		{id: 3, state: windows.WTSIdle},
		{id: 65536, state: windows.WTSListen, name: "RDP-Tcp"},
	}
	queried := map[uint32]bool{}
	user := func(id uint32) (string, error) {
		queried[id] = true
		switch id {
		case 1:
			return "", windows.ERROR_NO_TOKEN // sign-in screen
		case 2:
			return "", windows.ERROR_CTX_WINSTATION_NOT_FOUND // ended since enumeration
		}
		// A listener or idle session must never be asked: any error from
		// it used to make sign-out undetectable.
		return "", windows.ERROR_INVALID_PARAMETER
	}
	present, err := ownerInSessions("S-1-5-21-1-2-3-1001", sessions, user)
	if present || err != nil {
		t.Fatal("signed-out owner was not cleanly absent", present, err)
	}
	if queried[0] || queried[3] || queried[65536] {
		t.Fatal("queried a session that cannot have a user", queried)
	}
}

func TestWTSOwnerLookupKeepsRealErrorsUncertain(t *testing.T) {
	sessions := []wtsSession{{id: 1, state: windows.WTSActive}, {id: 2, state: windows.WTSActive}}
	failing := func(id uint32) (string, error) {
		if id == 1 {
			return "", windows.ERROR_ACCESS_DENIED
		}
		return "S-1-5-21-other", nil
	}
	if present, err := ownerInSessions("S-1-5-21-owner", sessions, failing); present || err == nil {
		t.Fatal("an unreadable session was treated as sign-out", present, err)
	}
	found := func(id uint32) (string, error) {
		if id == 1 {
			return "", windows.ERROR_ACCESS_DENIED
		}
		return "S-1-5-21-owner", nil
	}
	if present, err := ownerInSessions("S-1-5-21-owner", sessions, found); !present || err != nil {
		t.Fatal("a positive owner match must win over other lookup errors", present, err)
	}
}
