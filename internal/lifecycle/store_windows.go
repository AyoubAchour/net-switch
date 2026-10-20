package lifecycle

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	win "github.com/AyoubAchour/net-switch/internal/platform/windows"
	"golang.org/x/sys/windows"
)

func DefaultData() string { return filepath.Join(os.Getenv("ProgramData"), "Net Switch") }
func Administrator() bool { return windows.GetCurrentProcessToken().IsElevated() }
func CurrentUser() string {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return ""
	}
	return u.User.Sid.String()
}
func ResolveOwner(name string) (Owner, error) {
	if name == "" {
		return Owner{}, errors.New("enrolment pending: specify the interactive user's name or SID")
	}
	sid, err := windows.StringToSid(name)
	if err != nil {
		sid, _, _, err = windows.LookupSID("", name)
	}
	if err != nil {
		return Owner{}, err
	}
	user, domain, kind, err := sid.LookupAccount("")
	if err != nil {
		return Owner{}, err
	}
	if kind != windows.SidTypeUser {
		return Owner{}, errors.New("owner must be a user account")
	}
	return Owner{User: sid.String(), Name: domain + `\` + user}, nil
}
func PrepareDirectory(path string) error {
	if !Administrator() {
		return errors.New("creating the service store requires an administrator")
	}
	return win.ProtectDirectory(path)
}
func CheckDirectory(path string) error {
	// ProtectDirectory checks the independent HKLM certificate before reusing
	// any existing tree; it never trusts a folder just because its ACL looks new.
	return PrepareDirectory(path)
}
func SyncDirectory(string) error {
	// NTFS file handles are flushed before atomic replacement. Windows does
	// not implement FlushFileBuffers on a directory handle.
	return nil
}
func durableRename(from, to string) error {
	src, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	dst, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(src, dst, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
func BootID() (string, error) {
	var info struct {
		ID       windows.GUID
		Firmware uint32
		Flags    uint64
	}
	var size uint32
	if err := windows.NtQuerySystemInformation(90, unsafe.Pointer(&info), uint32(unsafe.Sizeof(info)), &size); err != nil {
		return "", err
	}
	return info.ID.String(), nil
}

type Lock struct{ Data, Name string }

func (l Lock) Acquire(ctx context.Context) (func() error, error) {
	result := make(chan error, 1)
	release := make(chan struct{})
	done := make(chan error, 1)
	digest := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(l.Data)) + "\x00" + l.Name))
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
		if err != nil {
			result <- err
			return
		}
		sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
		name, _ := windows.UTF16PtrFromString(fmt.Sprintf(`Global\NetSwitch-%x`, digest[:16]))
		handle, err := windows.CreateMutex(&sa, false, name)
		if err != nil && err != windows.ERROR_ALREADY_EXISTS {
			result <- err
			return
		}
		defer windows.CloseHandle(handle)
		for {
			state, err := windows.WaitForSingleObject(handle, 20)
			if err != nil {
				result <- err
				return
			}
			if state == windows.WAIT_OBJECT_0 || state == windows.WAIT_ABANDONED {
				result <- nil
				<-release
				done <- windows.ReleaseMutex(handle)
				return
			}
			if ctx.Err() != nil {
				result <- ctx.Err()
				return
			}
		}
	}()
	if err := <-result; err != nil {
		return nil, err
	}
	var once sync.Once
	var err error
	return func() error { once.Do(func() { close(release); err = <-done }); return err }, nil
}
