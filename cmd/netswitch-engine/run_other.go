//go:build !windows

package main

import "errors"

func run([]string) error {
	return errors.New("engine platform is not implemented on this operating system")
}
