package lifecycle

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestNativeCommitSurvivesAConcurrentStatusReader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outcome.json")
	if err := os.WriteFile(path, []byte("pending"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".next", []byte("complete"), 0600); err != nil {
		t.Fatal(err)
	}
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	attempts := 0
	err = replaceNativeStateWith(path+".next", path, func(from, to string) error {
		attempts++
		err := durableRename(from, to)
		if attempts == 1 {
			if !errors.Is(err, windows.ERROR_ACCESS_DENIED) && !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
				t.Fatal("reader did not reproduce the replacement conflict", err)
			}
			if closeErr := reader.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
		}
		return err
	})
	if err != nil || attempts != 2 {
		t.Fatal("status reader failed the durable commit", attempts, err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "complete" {
		t.Fatal(string(b), err)
	}
}

func TestNativeCommitPermissionFailureIsBounded(t *testing.T) {
	start := time.Now()
	err := replaceNativeStateWith("", "", func(string, string) error { return windows.ERROR_ACCESS_DENIED })
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) || time.Since(start) > time.Second {
		t.Fatal(err, time.Since(start))
	}
}
