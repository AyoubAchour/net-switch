//go:build !lifecycle_test

package faultpoint

import "time"

// Hit is compiled away in product builds.
func Hit(string, string)                                                           {}
func RestartDecayWindow(string) (time.Duration, bool)                              { return 0, false }
func OwnerSession(string, string) (bool, bool)                                     { return false, false }
func ProbeSession(string, func(string, uint32) (bool, error), func() string) error { return nil }
