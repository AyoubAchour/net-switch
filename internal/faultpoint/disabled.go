//go:build !lifecycle_test

package faultpoint

// Hit is compiled away in product builds.
func Hit(string, string)                       {}
func OwnerSession(string, string) (bool, bool) { return false, false }
