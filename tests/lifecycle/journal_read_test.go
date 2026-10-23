package lifecycle_test

import (
	"encoding/json"
	"time"
)

// readJournal reads a file that Control publishes with an atomic rename. The
// platform opener shares delete access, but a rename can still briefly refuse
// an open, so retry for a bounded time before reporting the read failure.
func readJournal(path string, value any) error {
	deadline := time.Now().Add(2 * time.Second)
	for {
		data, err := readFileShared(path)
		if err == nil {
			err = json.Unmarshal(data, value)
		}
		if err == nil || time.Now().After(deadline) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}
