//go:build windows

package winengine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const privateSDDL = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

func security(sddl string) (*windows.SecurityAttributes, error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, nil
}

// StateDirectory creates with the final ACL, rather than tightening a folder
// after someone may already have obtained a WRITE_DAC handle. It returns a
// handle which prevents replacement while the engine is using its files.
func StateDirectory(path string) (*os.File, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		p, err := windows.UTF16PtrFromString(parent)
		if err != nil {
			return nil, err
		}
		attr, err := windows.GetFileAttributes(p)
		if err != nil {
			return nil, err
		}
		if attr&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return nil, errors.New("state ancestor is a reparse point")
		}
		if filepath.Dir(parent) == parent {
			break
		}
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	sa, err := security(privateSDDL)
	if err != nil {
		return nil, err
	}
	if err := windows.CreateDirectory(p, sa); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return nil, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return nil, errors.New("engine state must be a regular directory")
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return nil, err
	}
	if !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !owner.IsWellKnown(windows.WinLocalSystemSid) {
		return nil, errors.New("engine state directory must be owned by Administrators or SYSTEM")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return nil, errors.New("engine state has no private DACL")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return nil, err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return nil, errors.New("unexpected state directory ACE")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !sid.IsWellKnown(windows.WinLocalSystemSid) {
			return nil, errors.New("engine state is accessible to non-administrators")
		}
	}
	for _, name := range []string{"engine-journal.json", "engine-state.json"} {
		child := filepath.Join(path, name)
		if info, err := os.Lstat(child); err == nil {
			if !info.Mode().IsRegular() {
				return nil, fmt.Errorf("%s is not a regular file", name)
			}
			ptr, _ := windows.UTF16PtrFromString(child)
			file, err := windows.CreateFile(ptr, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
				nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
			if err != nil {
				return nil, err
			}
			var info windows.ByHandleFileInformation
			err = windows.GetFileInformationByHandle(file, &info)
			windows.CloseHandle(file)
			if err != nil {
				return nil, err
			}
			if info.NumberOfLinks != 1 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
				return nil, fmt.Errorf("%s is a link", name)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	ok = true
	return f, nil
}

// FileStore flushes the Windows file handle before every mutation. NTFS commits
// the file's metadata with FlushFileBuffers; Windows has no directory fsync
// operation corresponding to Unix's separate directory durability step.
func SyncParent(string) error { return nil }

type OwnershipLock struct{}

// Win32 mutex ownership belongs to a thread, not a goroutine. The dedicated
// locked thread acquires AND releases it, including abandoned-owner recovery.
func (OwnershipLock) Acquire(ctx context.Context) (func() error, error) {
	acquired := make(chan error, 1)
	release := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		sa, err := security("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
		if err != nil {
			acquired <- err
			return
		}
		name, _ := windows.UTF16PtrFromString(`Global\NetSwitchEngineOwnership-` + wintunMutexID)
		h, err := windows.CreateMutex(sa, false, name)
		if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			acquired <- err
			return
		}
		defer windows.CloseHandle(h)
		for {
			if err := ctx.Err(); err != nil {
				acquired <- err
				return
			}
			status, err := windows.WaitForSingleObject(h, 50)
			if err != nil {
				acquired <- err
				return
			}
			if status == uint32(windows.WAIT_TIMEOUT) {
				continue
			}
			if status != windows.WAIT_OBJECT_0 && status != windows.WAIT_ABANDONED {
				acquired <- fmt.Errorf("ownership mutex wait: %d", status)
				return
			}
			break
		}
		acquired <- nil
		<-release
		result <- windows.ReleaseMutex(h)
	}()
	if err := <-acquired; err != nil {
		return nil, err
	}
	var once sync.Once
	var err error
	return func() error { once.Do(func() { close(release); err = <-result }); return err }, nil
}

const wintunMutexID = "D9B44E84-B5C7-4DC4-97A4-4E7CA6722686"

func bootIdentity() (string, error) {
	var info struct {
		ID       windows.GUID
		Firmware uint32
		Flags    uint64
	}
	var length uint32
	status, _, _ := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQuerySystemInformation").Call(
		90, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info), uintptr(unsafe.Pointer(&length)))
	if status != 0 {
		return "", fmt.Errorf("read Windows boot identity: status %#x", status)
	}
	return info.ID.String(), nil
}

func Elevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func waitContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
