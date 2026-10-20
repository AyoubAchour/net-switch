package lifecycle

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

func ownerSessionPresent(owner string, _ uint32) (bool, error) {
	if owner == "" {
		return false, nil
	}
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		return false, err
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	var uncertain error
	for _, session := range unsafe.Slice(sessions, count) {
		if session.SessionID == 0 {
			continue
		}
		var token windows.Token
		if err := windows.WTSQueryUserToken(session.SessionID, &token); err != nil {
			if !errors.Is(err, windows.ERROR_NO_TOKEN) {
				uncertain = errors.Join(uncertain, err)
			}
			continue
		}
		user, err := token.GetTokenUser()
		token.Close()
		if err != nil {
			uncertain = errors.Join(uncertain, err)
			continue
		}
		// Disconnected RDP sessions remain signed in. Desktop process death
		// also does not constitute a sign-out.
		if user.User.Sid.String() == owner {
			return true, nil
		}
	}
	// An incomplete enumeration is unknown, not evidence of logoff.
	return false, uncertain
}
