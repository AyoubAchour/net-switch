package lifecycle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	win "github.com/AyoubAchour/net-switch/internal/platform/windows"
	"github.com/AyoubAchour/net-switch/internal/winlock"
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
func PrepareStore(path string) (string, error) {
	if !Administrator() {
		return "", errors.New("creating the service store requires an administrator")
	}
	return win.PrepareMachineDirectory(path)
}
func ResolveStore(path string) (string, error) { return win.ResolveMachineDirectory(path) }
func CheckDirectory(path string) error {
	return win.VerifyDirectory(path)
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
func writeStoreFile(path string, data []byte, _ os.FileMode) error {
	// Installer/ctl writes must not leave their interactive user as the
	// owner, who could then rewrite the DACL from an unelevated process.
	sd, err := windows.SecurityDescriptorFromString("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(h), path)
	_, writeErr := f.Write(data)
	return errors.Join(writeErr, f.Close())
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
	if l.Name != "engine" && l.Name != "enrollment" {
		return nil, errors.New("invalid machine lock name")
	}
	if err := CheckDirectory(l.Data); err != nil {
		return nil, err
	}
	// The pathname is inside the verified store. Unprivileged users cannot
	// plant it, unlike a Global mutex. A byte-range lock dies with the handle.
	sd, err := windows.SecurityDescriptorFromString("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, err := windows.UTF16PtrFromString(filepath.Join(l.Data, l.Name+".lock"))
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, &sa, windows.OPEN_ALWAYS, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.NumberOfLinks != 1 {
		windows.CloseHandle(h)
		return nil, errors.New("machine lock is not a regular single-link file")
	}
	if err := winlock.Acquire(ctx, h); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	var once sync.Once
	var closeErr error
	return func() error { once.Do(func() { closeErr = windows.CloseHandle(h) }); return closeErr }, nil
}
