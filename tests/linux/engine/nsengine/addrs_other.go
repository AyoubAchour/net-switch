//go:build !linux

package nsengine

import (
	"context"
	"errors"
	"net/netip"
)

func lineAddresses(context.Context, string, string) ([]netip.Addr, error) {
	return nil, errors.New("line addresses are read in a Linux network namespace")
}
