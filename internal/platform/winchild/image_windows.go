//go:build windows

package winchild

import (
	"errors"
	"os"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

type FileID struct {
	Volume uint64
	Index  [16]byte
}

// Capture at process initialization, not at the first child launch: an updater
// can rename this running image and place another file at its load-time path.
var startupImageID, startupImageError = func() (FileID, error) {
	path, err := os.Executable()
	if err != nil {
		return FileID{}, err
	}
	return imageIDAt(path)
}()

func fileID(handle windows.Handle) (FileID, error) {
	var id FileID // FILE_ID_INFO: aligned volume serial and 128-bit file index
	err := windows.GetFileInformationByHandleEx(handle, windows.FileIdInfo, (*byte)(unsafe.Pointer(&id)), uint32(unsafe.Sizeof(id)))
	return id, err
}

func imageIDAt(path string) (FileID, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return FileID{}, err
	}
	h, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return FileID{}, err
	}
	owner := winhandle.Open(h, "child image identity open")
	id, err := fileID(h)
	return id, errors.Join(err, owner.HandleClose("child image identity close"))
}
