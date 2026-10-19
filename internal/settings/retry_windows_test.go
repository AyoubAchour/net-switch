package settings

import "syscall"

func retryErrors() []error { return []error{syscall.Errno(5), syscall.Errno(32), syscall.Errno(33)} }
