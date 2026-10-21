//go:build linux

package linux

import "github.com/AyoubAchour/net-switch/internal/engine/platform"

// The engine finds the optional interfaces by type assertion, so a signature
// drift would still compile and silently take the fallback: for ReadyTCP, one
// goroutine per flow instead of the shared readiness relay. These make any
// drift a build error.
var (
	_ platform.TCPConn  = (*tcpSocket)(nil)
	_ platform.ReadyTCP = (*tcpSocket)(nil)

	_ platform.UDPConn         = (*udpSocket)(nil)
	_ platform.ReadyUDP        = (*udpSocket)(nil)
	_ platform.UDPErrorHandler = (*udpSocket)(nil)
	_ platform.UDPErrorQueue   = (*udpSocket)(nil)

	_ platform.TunDevice    = (*Tun)(nil)
	_ platform.TunIOContext = (*Tun)(nil)
	_ platform.BatchWriter  = (*Tun)(nil)

	_ platform.LineDialer        = (*Platform)(nil)
	_ platform.DestinationDialer = (*Platform)(nil)
	_ platform.RouteManager      = (*Platform)(nil)
	_ platform.RouteQuiescer     = (*Platform)(nil)
	_ platform.Prober            = (*Platform)(nil)
	_ platform.Echoer            = (*Platform)(nil)

	_ platform.OwnerLookup         = (*Owners)(nil)
	_ platform.DatagramOwnerLookup = (*Owners)(nil)
	_ platform.UDPIdentity         = (*Owners)(nil)
	_ platform.UDPIdentityAt       = (*Owners)(nil)
	_ platform.UDPNotifications    = (*Owners)(nil)
)
