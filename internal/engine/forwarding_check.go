package engine

import (
	"crypto/subtle"
	"errors"
	"net"

	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type forwardingInfo struct {
	index int
	port  uint16
}
type forwardingCheck struct {
	*gonet.UDPConn
	done chan struct{}
}

func (c *forwardingCheck) Close() { c.UDPConn.Close(); <-c.done }

func (e *Engine) ForwardingCheck() (int, uint16) {
	if info := e.healthInfo.Load(); info != nil {
		return info.index, info.port
	}
	return 0, 0
}

// This endpoint is inside the child's netstack, not an OS listener. Its only
// valid sender is the host's TUN-bound socket carrying the private 256-bit key.
// A reply traverses both actual TUN pumps and gVisor UDP; no WAN is involved.
func (e *Engine) startForwardingCheck() error {
	if len(e.deps.HealthKey) == 0 {
		return nil
	}
	indexer, ok := e.deps.Routes.(interface{ ForwardingIndex() int })
	if !ok || len(e.deps.HealthKey) != 32 || indexer.ForwardingIndex() <= 0 {
		return errors.New("missing private forwarding identity")
	}
	addr := tcpip.AddrFrom4([4]byte{198, 18, 0, 2})
	if err := e.stack.AddProtocolAddress(ns.NIC, tcpip.ProtocolAddress{Protocol: header.IPv4ProtocolNumber, AddressWithPrefix: addr.WithPrefix()}, gv.AddressProperties{}); err != nil {
		return errors.New(err.String())
	}
	var queue waiter.Queue
	ep, err := e.stack.NewEndpoint(udp.ProtocolNumber, header.IPv4ProtocolNumber, &queue)
	if err != nil {
		return errors.New(err.String())
	}
	ep.SocketOptions().SetReceiveBufferSize(4096, true)
	ep.SocketOptions().SetSendBufferSize(4096, true)
	if err := ep.Bind(tcpip.FullAddress{NIC: ns.NIC, Addr: addr}); err != nil {
		ep.Close()
		return errors.New(err.String())
	}
	c := &forwardingCheck{UDPConn: gonet.NewUDPConn(&queue, ep), done: make(chan struct{})}
	key := append([]byte(nil), e.deps.HealthKey...)
	e.health = c
	e.healthInfo.Store(&forwardingInfo{indexer.ForwardingIndex(), uint16(c.LocalAddr().(*net.UDPAddr).Port)})
	go func() {
		defer close(c.done)
		var b [41]byte
		for {
			n, peer, err := c.ReadFrom(b[:])
			if err != nil {
				return
			}
			from, ok := peer.(*net.UDPAddr)
			if !ok || !from.IP.Equal(net.IPv4(198, 18, 0, 1)) || n != 40 || subtle.ConstantTimeCompare(key, b[:32]) != 1 {
				continue
			}
			if _, err := c.WriteTo(b[:n], peer); err != nil {
				return
			}
		}
	}()
	return nil
}
