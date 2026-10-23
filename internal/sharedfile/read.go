// Package sharedfile reads atomically published state without excluding its
// publisher. Only Windows sharing violations receive a bounded retry.
package sharedfile

import (
	"errors"
	"io"
	"time"
)

// ReadFile reads at most limit+1 bytes so callers can enforce their existing
// size errors. A negative limit preserves an unbounded reader's semantics.
// Missing-file and permission errors are returned unchanged, without retry.
func ReadFile(path string, limit int64) ([]byte, error) {
	deadline := time.Now().Add(2 * time.Second)
	for {
		data, err := readOnce(path, limit)
		if err == nil || !sharingViolation(err) || !time.Now().Before(deadline) {
			return data, err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func readOnce(path string, limit int64) ([]byte, error) {
	file, err := openFile(path)
	if err != nil {
		return nil, err
	} // keep *os.PathError for os.IsNotExist
	var reader io.Reader = file
	if limit >= 0 {
		reader = io.LimitReader(file, limit+1)
	}
	data, err := io.ReadAll(reader)
	return data, errors.Join(err, file.Close())
}
