//go:build windows && !netswitch_handlecheck

package winhandle

import "golang.org/x/sys/windows"

const Enabled = false

func opened(windows.Handle, string) uint64 { return 1 }
func used(Owner, string, bool)             {}
func closing(Owner, string, bool)          {}
func closed(Owner, string, error)          {}
func driverOwned(Owner)                    {}
func driverReleased(Owner, string)         {}
func Stats() any                           { return nil }
