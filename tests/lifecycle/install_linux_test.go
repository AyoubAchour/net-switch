package lifecycle_test

import (
	"os"
	"testing"
)

func writableInstallPath(t *testing.T, path string) func() {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, info.Mode().Perm()|0022); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := os.Chmod(path, info.Mode().Perm()); err != nil {
			t.Fatal(err)
		}
	}
}
