//go:build !windows

package settings

import (
	"errors"
	"syscall"
)

func retryable(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EBUSY) || errors.Is(err, syscall.EACCES)
}
