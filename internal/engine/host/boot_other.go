//go:build !linux

package host

func CurrentBootID() (string, error) { return "", nil }
