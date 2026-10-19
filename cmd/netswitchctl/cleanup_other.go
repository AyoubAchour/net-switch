//go:build !linux

package main

import "errors"

func run([]string) error {
	return errors.New("usage: netswitchctl version (cleanup is not implemented on this platform yet)")
}
