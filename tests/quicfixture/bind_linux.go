//go:build linux

package main

import "syscall"

// soBindToIfindex is SO_BINDTOIFINDEX (Linux 5.0): bind by interface index.
const soBindToIfindex = 62

func bindInterface(index int) func(string, string, syscall.RawConn) error {
	return func(_, _ string, raw syscall.RawConn) error {
		var sockErr error
		if err := raw.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soBindToIfindex, index)
		}); err != nil {
			return err
		}
		return sockErr
	}
}
