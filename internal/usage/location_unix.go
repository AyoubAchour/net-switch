//go:build !windows

package usage

import "time"

// Unix time.Local reads the complete system zoneinfo history.
func LocalLocation() (*time.Location, error) { return time.Local, nil }
