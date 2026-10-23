//go:build !windows

package lifecycle_test

import "os"

func readFileShared(path string) ([]byte, error) { return os.ReadFile(path) }
