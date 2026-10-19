//go:build windows

package main

import (
	"context"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

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
	link := channel.New(1024, 1500, "")
	if err := s.CreateNIC(1, link); err != nil {
		s.Close()
		return nil, netstackError{err}
	}
	s.SetPromiscuousMode(1, true)
	s.SetSpoofing(1, true)
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	// The harness must not add its own TIME_WAIT freeze to the engine under test.
	wait := tcpip.TCPTimeWaitTimeoutOption(0)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &wait)
	forwarder := tcp.NewForwarder(s, 64*1024, 2048, func(request *tcp.ForwarderRequest) {
		go func() {
			id := request.ID()
			destination := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
			g.record(destination)
			remote, err := boundDialer(g.index, g.uplinkIP).DialContext(context.Background(), "tcp4", g.backend(destination))
			if err != nil {
				g.failure(destination, err)
				request.Complete(true)
				return
			}
			defer remote.Close()
			var queue waiter.Queue
			endpoint, terr := request.CreateEndpoint(&queue)
			if terr != nil {
				request.Complete(true)
				g.failure(destination, netstackError{terr})
				return
			}
			request.Complete(false)
			local := gonet.NewTCPConn(&queue, endpoint)
			defer local.Close()
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				n, _ := io.Copy(remote, local)
				remote.(*net.TCPConn).CloseWrite()
				g.transferred(n, true)
			}()
			go func() { defer wg.Done(); n, _ := io.Copy(local, remote); local.CloseWrite(); g.transferred(n, false) }()
			wg.Wait()
		}()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, forwarder.HandlePacket)
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
				_, err := g.device.Write([][]byte{data}, 0)
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
		sizes := []int{0}
		for {
			if g.mode.Load() == 1 {
				select {
				case <-g.done:
					return
				case <-time.After(10 * time.Millisecond):
				}
				continue
			}
			_, err := g.device.Read([][]byte{packet}, sizes, 0)
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
			n := sizes[0]
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
			// gVisor can answer echo locally. Only our controlled target is local;
			// never manufacture a reply for a public host that we did not ping.
			if n >= 20 && packet[0]>>4 == 4 && packet[9] == 1 && net.IP(packet[16:20]).String() != "198.19.128.2" {
				continue
			}
			if n >= 40 && packet[0]>>4 == 6 && packet[6] == 58 && net.IP(packet[24:40]).String() != "2001:db8:198::2" {
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
