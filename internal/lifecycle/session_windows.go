package lifecycle

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

type wtsSession struct {
	id, state uint32
	name      string
}

func ownerSessionPresent(owner string, _ uint32) (bool, error) {
	if owner == "" {
		return false, nil
	}
	sessions, err := wtsSessions()
	if err != nil {
		return false, err
	}
	return ownerInSessions(owner, sessions, wtsSessionUser)
}

// ownerInSessions finds the owner's SID among the users of the sessions.
// Any other failure leaves the answer unknown rather than absent, because
// an incomplete enumeration is not evidence of sign-out.
func ownerInSessions(owner string, sessions []wtsSession, user func(uint32) (string, error)) (bool, error) {
	var uncertain error
	for _, session := range sessions {
		if !userSession(session) {
			continue
		}
		sid, err := user(session.id)
		if err != nil {
			// No token: nobody is signed in to the session (yet). Not
			// found: it ended between enumeration and this query.
			if errors.Is(err, windows.ERROR_NO_TOKEN) || errors.Is(err, windows.ERROR_CTX_WINSTATION_NOT_FOUND) {
				continue
			}
			uncertain = errors.Join(uncertain, fmt.Errorf("session %d (%s, state %d): %w", session.id, session.name, session.state, err))
			continue
		}
		// Disconnected RDP sessions remain signed in. Desktop process death
		// also does not constitute a sign-out.
		if sid == owner {
			return true, nil
		}
	}
	return false, uncertain
}

// userSession excludes sessions that cannot have a signed-in user: session 0
// runs services, a listener session (RDP-Tcp's is 65536) only waits for new
// connections, and an idle session is waiting for a client to connect. See
// Microsoft's WTS_CONNECTSTATE_CLASS.
func userSession(s wtsSession) bool {
	return s.id != 0 && s.state != windows.WTSListen && s.state != windows.WTSIdle
}

func wtsSessions() ([]wtsSession, error) {
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		return nil, err
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	out := make([]wtsSession, 0, count)
	for _, s := range unsafe.Slice(sessions, count) {
		out = append(out, wtsSession{id: s.SessionID, state: s.State, name: windows.UTF16PtrToString(s.WindowStationName)})
	}
	return out, nil
}

func wtsSessionUser(id uint32) (string, error) {
	var token windows.Token
	if err := windows.WTSQueryUserToken(id, &token); err != nil {
		return "", err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String(), nil
}

// describeSessions lists every session with its raw token result, so a
// hosted probe shows which session kinds the runner really has.
func describeSessions() string {
	sessions, err := wtsSessions()
	if err != nil {
		return "enumeration failed: " + err.Error()
	}
	var parts []string
	for _, s := range sessions {
		result := "skipped"
		if s.id != 0 {
			if sid, err := wtsSessionUser(s.id); err != nil {
				result = "error " + err.Error()
			} else {
				result = "user " + sid
			}
		}
		parts = append(parts, fmt.Sprintf("id=%d state=%d name=%q counted=%t token=%s", s.id, s.state, s.name, userSession(s), result))
	}
	return strings.Join(parts, "; ")
}
