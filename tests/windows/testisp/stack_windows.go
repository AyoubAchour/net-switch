//go:build windows

package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/AyoubAchour/net-switch/internal/wintun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func (g *gateway) startStack() (*stack.Stack, error) {
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6}})
	g.stack = s
	link := channel.New(1024, 1500, "")
	if err := s.CreateNIC(1, link); err != nil {
		s.Close()
		return nil, netstackError{err}
	}
	s.SetPromiscuousMode(1, true)
	s.SetSpoofing(1, true)
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	// Promiscuous addresses are temporary; gVisor deliberately does not answer
	// IPv4 echo for them. The controlled responder has permanent stack addresses.
	for _, address := range []tcpip.ProtocolAddress{
		{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4([4]byte{198, 19, 128, 2}).WithPrefix()},
		{Protocol: ipv6.ProtocolNumber, AddressWithPrefix: tcpip.AddrFromSlice(net.ParseIP("2001:db8:198::2").To16()).WithPrefix()},
	} {
		if err := s.AddProtocolAddress(1, address, stack.AddressProperties{}); err != nil {
			s.Close()
			return nil, netstackError{err}
		}
	}
	forwarder := tcp.NewForwarder(s, 64*1024, 2048, func(request *tcp.ForwarderRequest) {
		connection, tuple := g.newConnection(request.ID())
		go func() {
			id := request.ID()
			destination := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
			g.record(destination)
			g.event("dial-start", connection, tuple, "")
			remote, err := boundDialer(g.index, g.uplinkIP).DialContext(context.Background(), "tcp4", g.backend(destination))
			if err != nil {
				g.event("dial-error", connection, tuple, err.Error())
				g.failure(destination, err)
				request.Complete(true)
				return
			}
			defer remote.Close()
			g.event("dial-end", connection, tuple, remote.LocalAddr().String())
			var queue waiter.Queue
			g.event("handshake-start", connection, tuple, "SYN-RCVD")
			endpoint, terr := request.CreateEndpoint(&queue)
			if terr != nil {
				request.Complete(true)
				g.failure(destination, netstackError{terr})
				return
			}
			request.Complete(false)
			g.event("handshake-end", connection, tuple, "")
			g.watchEndpoint(connection, tuple, endpoint)
			local := gonet.NewTCPConn(&queue, endpoint)
			defer local.Close()
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				n, err := io.Copy(remote, &observedReader{Reader: local, g: g, id: connection, tuple: tuple, direction: "client"})
				if err != nil {
					remote.(*net.TCPConn).SetLinger(0)
					remote.Close()
					endpoint.Abort()
				} else {
					remote.(*net.TCPConn).CloseWrite()
				}
				g.transferred(n, true)
			}()
			go func() {
				defer wg.Done()
				n, err := io.Copy(local, &observedReader{Reader: remote, g: g, id: connection, tuple: tuple, direction: "backend"})
				if err != nil {
					endpoint.Abort()
					remote.(*net.TCPConn).SetLinger(0)
					remote.Close()
				} else {
					local.CloseWrite()
					g.event("close-write", connection, tuple, "")
					g.states()
				}
				g.transferred(n, false)
			}()
			wg.Wait()
		}()
	})
	handle := func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		g.event("forwarder-handle", 0, id.RemoteAddress.String(), "")
		return forwarder.HandlePacket(id, pkt)
	}
	g.tcpReuseHook = configureTCPReuse(s, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		g.event("timewait-hook", 0, id.RemoteAddress.String(), "")
		return handle(id, pkt)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, handle)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, g.udpHandler(link))
	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { <-g.done; cancel() }()
		for {
			packet := link.ReadContext(ctx)
			if packet == nil {
				return
			}
			view := packet.ToView()
			data := view.AsSlice()
			if g.mode.Load() == 0 {
				g.trace(data, "reply")
				err := g.device.Write(data)
				if err != nil {
					g.event("wintun-write-error", 0, "", err.Error())
					if errors.Is(err, wintun.ErrAdapterRemoved) {
						view.Release()
						packet.DecRef()
						g.close()
						return
					}
				} else {
					g.trace(data, "delivered")
				}
				g.stats.Lock()
				if err != nil {
					g.stats.TestISP.Errors++
				} else {
					g.stats.TestISP.PacketsOut++
					g.stats.TestISP.BytesOut += uint64(len(data))
				}
				g.stats.Unlock()
			}
			view.Release()
			packet.DecRef()
		}
	}()
	go func() {
		packet := make([]byte, 65535)
		for {
			if g.mode.Load() == 1 {
				select {
				case <-g.done:
					return
				case <-time.After(10 * time.Millisecond):
				}
				continue
			}
			n, err := g.device.Read(packet)
			if err != nil {
				select {
				case <-g.done:
					return
				default:
					log.Print(err)
					g.close()
					return
				}
			}
			g.stats.Lock()
			g.stats.TestISP.PacketsIn++
			g.stats.TestISP.BytesIn += uint64(n)
			drop := g.mode.Load() != 0
			if drop {
				g.stats.TestISP.Dropped++
			}
			g.stats.Unlock()
			if drop || n == 0 {
				continue
			}
			g.trace(packet[:n], "request")
			echo := ""
			if n >= 28 && packet[0]>>4 == 4 && packet[9] == 1 && int(packet[0]&15)*4 < n && packet[int(packet[0]&15)*4] == 8 {
				echo = net.IP(packet[16:20]).String()
			}
			if n >= 48 && packet[0]>>4 == 6 && packet[6] == 58 && packet[40] == 128 {
				echo = net.IP(packet[24:40]).String()
			}
			if echo != "" {
				g.stats.Lock()
				if g.stats.EchoRequests == nil {
					g.stats.EchoRequests = make(map[string]uint64)
				}
				g.stats.EchoRequests[echo]++
				g.stats.Unlock()
			}
			// gVisor can answer echo locally. Only our controlled target is local;
			// never manufacture a reply for a public host that we did not ping.
			if n >= 20 && packet[0]>>4 == 4 && packet[9] == 1 && net.IP(packet[16:20]).String() != "198.19.128.2" {
				continue
			}
			if n >= 40 && packet[0]>>4 == 6 && net.IP(packet[24:40]).String() != "2001:db8:198::2" {
				continue
			}
			protocol := ipv4.ProtocolNumber
			if packet[0]>>4 == 6 {
				protocol = ipv6.ProtocolNumber
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), packet[:n]...))})
			link.InjectInbound(protocol, pkt)
			pkt.DecRef()
		}
	}()
	return s, nil
}

func configureTCPReuse(s *stack.Stack, handler func(stack.TransportEndpointID, *stack.PacketBuffer) bool) bool {
	// Install before the TUN reader starts; preserve the normal 60-second wait
	// for final ACK retransmission while allowing a fresh local-app SYN.
	tcp.SetTimeWaitHandler(s, handler)
	return true
}

type netstackError struct{ err tcpip.Error }

func (e netstackError) Error() string { return e.err.String() }

func (g *gateway) record(destination string) {
	g.stats.Lock()
	defer g.stats.Unlock()
	g.stats.TestISP.Connections++
	g.stats.Uplink.Connections++
	g.stats.Destinations[destination]++
}

func (g *gateway) failure(destination string, err error) {
	log.Printf("relay %s: %v", destination, err)
	g.stats.Lock()
	g.stats.Uplink.Errors++
	g.stats.Unlock()
}

func (g *gateway) transferred(n int64, outgoing bool) {
	g.stats.Lock()
	defer g.stats.Unlock()
	if outgoing {
		g.stats.Uplink.BytesOut += uint64(n)
	} else {
		g.stats.Uplink.BytesIn += uint64(n)
	}
}

func (g *gateway) backend(destination string) string {
	g.targetMu.RLock()
	defer g.targetMu.RUnlock()
	if address, ok := g.targets[destination]; ok {
		return address
	}
	return destination
}
