//go:build !linux

package main

import "errors"

func run([]string) error {
	return errors.New("usage: netswitch-engine version (routing is not implemented on this platform yet)")
}
