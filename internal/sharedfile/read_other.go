//go:build !windows

package sharedfile

import "os"

func openFile(path string) (*os.File, error) { return os.Open(path) }
func sharingViolation(error) bool            { return false }
