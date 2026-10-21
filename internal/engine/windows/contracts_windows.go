//go:build windows

package winengine

import "github.com/AyoubAchour/net-switch/internal/engine/platform"

// The engine finds the optional interfaces by type assertion, so a signature
// drift would still compile and silently take the fallback: for ReadyTCP and
// ReadyUDP, one goroutine per flow instead of the shared readiness relay.
// These make any drift a build error.
var (
	_ platform.TCPConn  = (*readySocket)(nil)
	_ platform.ReadyTCP = (*readySocket)(nil)

	_ platform.UDPConn  = (*udpSocket)(nil)
	_ platform.ReadyUDP = (*udpSocket)(nil)

	_ platform.TunDevice       = (*measuredTun)(nil)
	_ platform.BatchWriter     = (*measuredTun)(nil)
	_ platform.TunCloseStarter = (*measuredTun)(nil)

	_ platform.LineDialer = (*Dialer)(nil)
	_ platform.Prober     = (*Dialer)(nil)
	_ platform.Echoer     = (*Dialer)(nil)

	_ platform.RouteManager  = (*Routes)(nil)
	_ platform.RouteQuiescer = (*Routes)(nil)

	_ platform.OwnerLookup = (*Owners)(nil)
	_ platform.UDPIdentity = (*Owners)(nil)
)
