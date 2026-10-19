//go:build !windows

package settings

import "syscall"

func retryErrors() []error { return []error{syscall.EPERM, syscall.EBUSY, syscall.EACCES} }
