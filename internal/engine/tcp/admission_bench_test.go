package tcp

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// Only State is needed: an established endpoint cannot release admission.
// The real table holds every ticket, and Handle performs actual cap rejection.
type liveCapEndpoint struct{ tcpip.Endpoint }

func (*liveCapEndpoint) State() uint32 { return uint32(gtcp.StateEstablished) }

type discardCapOutput struct{}

func (discardCapOutput) Send([]byte) bool { return true }

func BenchmarkSYNAtCapacity(b *testing.B) {
	for _, count := range []int{10000, 65536} {
		for _, cap := range []string{"total", "handshake"} {
			b.Run(fmt.Sprintf("%s/%d", cap, count), func(b *testing.B) {
				limits := flows.Defaults()
				limits.Flows = count
				if cap == "handshake" {
					limits.Flows += 2
					limits.Handshakes = 1
				}
				table := flows.New(limits, nil)
				config := policy.Config{Lines: []platform.Line{{ID: "A"}}, IPv6: true}
				if _, err := table.Apply(policy.Revision{N: 1, Hash: policy.Hash(config), Config: config}); err != nil {
					b.Fatal(err)
				}
				f := &Forwarder{ctx: context.Background(), control: table, out: discardCapOutput{}, inFlight: limits.Handshakes,
					connections: make(map[gv.TransportEndpointID]*connection)}
				tuple := platform.Tuple{Source: netip.MustParseAddrPort("198.18.0.2:40000"), Destination: netip.MustParseAddrPort("203.0.113.7:443")}
				for i := range count {
					ticket, err := table.Begin("tcp", tuple)
					if err != nil {
						b.Fatal(err)
					}
					ticket.Established(netip.Addr{})
					id := gv.TransportEndpointID{RemotePort: uint16(i)}
					f.connections[id] = &connection{id: id, ep: &liveCapEndpoint{}, ticket: ticket}
				}
				if cap == "handshake" {
					if _, err := table.Begin("tcp", tuple); err != nil {
						b.Fatal(err)
					}
				}
				if g := table.Stats(); (cap == "total" && g.Flows != limits.Flows) || (cap == "handshake" && (g.Handshakes != 1 || g.Flows >= limits.Flows)) {
					b.Fatal("cap not occupied", g)
				}
				src := tcpip.AddrFrom4([4]byte{198, 18, 0, 2})
				dst := tcpip.AddrFrom4([4]byte{203, 0, 113, 7})
				raw := make([]byte, header.TCPMinimumSize)
				h := header.TCP(raw)
				h.Encode(&header.TCPFields{SrcPort: 40000, DstPort: 443, SeqNum: 1000, DataOffset: 20, Flags: header.TCPFlagSyn, WindowSize: 65535})
				h.SetChecksum(^checksum.Checksum(h, header.PseudoHeaderChecksum(gtcp.ProtocolNumber, src, dst, uint16(len(h)))))
				pkt := gv.NewPacketBuffer(gv.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
				defer pkt.DecRef()
				pkt.TransportHeader().Consume(header.TCPMinimumSize)
				id := gv.TransportEndpointID{RemoteAddress: src, LocalAddress: dst, RemotePort: 40000, LocalPort: 443}
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					f.Handle(id, pkt)
				}
				b.StopTimer()
				if f.Rejected.Load() != uint64(b.N) || table.Stats().Rejected != uint64(b.N) {
					b.Fatal("SYNs did not reach cap rejection")
				}
			})
		}
	}
}
