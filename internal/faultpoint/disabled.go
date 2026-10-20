//go:build !lifecycle_test

package faultpoint

// Hit is compiled away in product builds.
func Hit(string, string) {}
