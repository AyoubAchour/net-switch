package sharedfile

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func sharingViolation(err error) bool { return errors.Is(err, windows.ERROR_SHARING_VIOLATION) }

// openFile opens with FILE_SHARE_DELETE so a reader is not refused while
// another writer publishes a replacement. Control replaces the journal by
// renaming a temporary file over it, and MoveFileEx keeps a DELETE handle on
// the target for a moment. os.ReadFile omits FILE_SHARE_DELETE on Windows, and
// an admin command reading the journal can otherwise see a sharing violation.
func openFile(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}
