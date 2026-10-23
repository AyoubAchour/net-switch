// Package testproxy is a bounded acceptance aid, never a product ingress.
package testproxy

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

var ErrDisabled = errors.New("test proxy is disabled in product builds")

type Options struct {
	Address string
	Table   *flows.Table
	Owners  platform.OwnerLookup
	Dial    func(context.Context, string, netip.AddrPort) (net.Conn, error)
	// Listen is injected by pure tests; hosts use net.Listen on loopback only.
	Listen func(string, string) (net.Listener, error)
}

type Status struct {
	Address     string `json:"address"`
	Connections int    `json:"connections"`
}
