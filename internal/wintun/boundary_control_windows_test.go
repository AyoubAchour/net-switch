//go:build windows

package wintun

import "net"

type wordBoundaryCapture interface {
	bind(local string, transfer uint64, stream int)
	complete(transfer uint64, streams int) error
	echo(net.Conn) (int64, error)
	hostFailure(local string, difference *wordDifference, reason string) bool
}
