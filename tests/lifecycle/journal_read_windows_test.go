package lifecycle_test

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/windows"
)

// readFileShared opens with FILE_SHARE_DELETE. Control replaces the journal by
// renaming a temporary file over it, and MoveFileEx publishes the new name
// while it still holds a DELETE handle on the target. os.ReadFile omits
// FILE_SHARE_DELETE on Windows, so it can fail with a sharing violation inside
// that window even though the journal is complete and valid.
func readFileShared(path string) ([]byte, error) {
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
	file := os.NewFile(uintptr(handle), path)
	data, readErr := io.ReadAll(file)
	return data, errors.Join(readErr, file.Close())
}
