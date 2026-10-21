//go:build !linux && !windows

package main

import "errors"

func run([]string) error {
	return errors.New("usage: netswitch-engine version|service|worker (routing is not implemented on this platform yet)")
}
