package lifecycle

import (
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// readStoreFile opens with FILE_SHARE_DELETE so a reader is not refused while
// another writer publishes a replacement. Control replaces the journal by
// renaming a temporary file over it, and MoveFileEx keeps a DELETE handle on
// the target for a moment. os.ReadFile omits FILE_SHARE_DELETE on Windows, and
// an admin command reading the journal can otherwise see a sharing violation.
func readStoreFile(path string) ([]byte, error) {
	deadline := time.Now().Add(2 * time.Second)
	for {
		data, err := openSharedRead(path)
		if err == nil || !errors.Is(err, windows.ERROR_SHARING_VIOLATION) || time.Now().After(deadline) {
			return data, err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func openSharedRead(path string) ([]byte, error) {
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
