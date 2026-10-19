//go:build !linux && !windows

package main

import (
	"errors"
	"syscall"
)

func bindInterface(int) func(string, string, syscall.RawConn) error {
	return func(string, string, syscall.RawConn) error {
		return errors.New("--interface is supported on Linux and Windows only")
	}
}
