//go:build windows

package wintun

import (
	"fmt"
	"net"
)

func wordBoundaryRingFault(f *fixture) error {
	if f != nil {
		if s, ok := f.io.(*Session); ok {
			if n := s.Stats().Corruptions; n != 0 {
				return fmt.Errorf("%w: %d unexpected ring validation rejections", errPayloadIntegrity, n)
			}
		}
	}
	return nil
}

type wordBoundaryCapture interface {
	bind(local string, transfer uint64, stream int)
	complete(transfer uint64, streams int) error
	echo(net.Conn) (int64, error)
	hostFailure(local string, difference *wordDifference, reason string) bool
}
