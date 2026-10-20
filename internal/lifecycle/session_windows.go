package lifecycle

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

var querySession = windows.NewLazySystemDLL("wtsapi32.dll").NewProc("WTSQuerySessionInformationW")

func ownerSessionPresent(owner string, excluded uint32) (bool, error) {
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		return false, err
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	read := func(id, class uint32) (string, error) {
		var data *uint16
		var size uint32
		ok, _, err := querySession.Call(0, uintptr(id), uintptr(class), uintptr(unsafe.Pointer(&data)), uintptr(unsafe.Pointer(&size)))
		if ok == 0 {
			return "", err
		}
		defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(data)))
		if data == nil || size < 2 || size > 65536 {
			return "", errors.New("invalid session name")
		}
		return windows.UTF16ToString(unsafe.Slice(data, size/2)), nil
	}
	for _, session := range unsafe.Slice(sessions, count) {
		if session.SessionID == 0 || session.SessionID == excluded {
			continue
		}
		name, err := read(session.SessionID, 5) // WTSUserName
		if err != nil {
			return false, err
		}
		if name == "" {
			continue
		}
		domain, err := read(session.SessionID, 7) // WTSDomainName
		if err != nil {
			return false, err
		}
		if domain != "" {
			name = domain + `\` + name
		}
		sid, _, _, err := windows.LookupSID("", name)
		if err != nil {
			return false, err
		}
		// Disconnected RDP sessions remain signed in. Desktop process death
		// also does not constitute a sign-out.
		if sid.String() == owner {
			return true, nil
		}
	}
	return false, nil
}
