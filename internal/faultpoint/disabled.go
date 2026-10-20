//go:build !lifecycle_test

package faultpoint

// Hit is compiled away in product builds.
func Hit(string, string)                                            {}
func OwnerSession(string, string) (bool, bool)                      { return false, false }
func ProbeSession(string, func(string, uint32) (bool, error)) error { return nil }
