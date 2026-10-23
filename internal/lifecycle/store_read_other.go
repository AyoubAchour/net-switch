//go:build !windows

package lifecycle

import "os"

func readStoreFile(path string) ([]byte, error) { return os.ReadFile(path) }
