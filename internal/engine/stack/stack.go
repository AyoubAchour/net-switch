// Package stack configures the packet stack without opening any OS devices.
package stack

import (
	"fmt"
	"runtime"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const MTU = 9000
const NIC tcpip.NICID = 1

type Options struct {
	Clock           tcpip.Clock
	ClockResolution time.Duration
	TimeWait        time.Duration
}

func DefaultOptions() Options {
	// Keep lost-final-ACK protection. The forwarder installs the local-app
	// SYN reopen hook; see TestTimeWaitImmediateReuse.
	o := Options{TimeWait: 60 * time.Second}
	if runtime.GOOS == "windows" {
		o.ClockResolution = 500 * time.Microsecond
	}
	return o
}

// OrderedLink completes close processing before admitting the next packet.
type OrderedLink interface {
	gv.LinkEndpoint
	SetAfterInbound(func())
}

func New(link OrderedLink, o Options) (*gv.Stack, error) {
	s := gv.New(gv.Options{
		NetworkProtocols:   []gv.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []gv.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
		Clock:              o.Clock, ClockResolution: o.ClockResolution,
	})
	fail := func(err tcpip.Error) (*gv.Stack, error) {
		s.Close()
		s.Wait()
		return nil, fmt.Errorf("configure stack: %s", err)
	}
	congestion := tcpip.CongestionControlOption("cubic")
	for _, opt := range []tcpip.SettableTransportProtocolOption{
		&congestion,
		&tcpip.TCPReceiveBufferSizeRangeOption{Min: 64 << 10, Default: 64 << 10, Max: 8 << 20},
		&tcpip.TCPSendBufferSizeRangeOption{Min: 64 << 10, Default: 64 << 10, Max: 6 << 20},
	} {
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, opt); err != nil {
			return fail(err)
		}
	}
	tw := tcpip.TCPTimeWaitTimeoutOption(o.TimeWait)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &tw); err != nil {
		return fail(err)
	}
	if err := s.CreateNIC(NIC, link); err != nil {
		return fail(err)
	}
	if err := s.SetPromiscuousMode(NIC, true); err != nil {
		return fail(err)
	}
	if err := s.SetSpoofing(NIC, true); err != nil {
		return fail(err)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: NIC},
		{Destination: header.IPv6EmptySubnet, NIC: NIC},
	})
	link.SetAfterInbound(func() { tcp.DrainLocalClose(s) })
	return s, nil
}
