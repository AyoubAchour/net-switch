package tcp

import (
	"context"
	"testing"

	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// Review of 822789db: the silent-SYN diagnostics are the platform's opt-in
// (Windows). Off, as on Linux, a duplicate SYN is answered as before they
// existed: nothing is recorded and stats carry no section. On, it is noted
// with its endpoints and reason.
func TestSilentSYNDiagnosticsAreOptIn(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		l := ns.NewLink()
		s, err := ns.New(l, ns.DefaultOptions())
		if err != nil {
			t.Fatal(err)
		}
		c := &testfake.Controller{}
		f := New(context.Background(), s, 2, c, &testfake.Owners{}, testfake.Dialer{}, l)
		if enabled {
			f.RecordSilentSYNs()
		}
		src, dst := tcpip.AddrFrom4([4]byte{198, 18, 0, 2}), tcpip.AddrFrom4([4]byte{203, 0, 113, 7})
		id := gv.TransportEndpointID{RemoteAddress: src, LocalAddress: dst, RemotePort: 40000, LocalPort: 443}
		// A SYN whose first copy is still being opened: a duplicate.
		f.mu.Lock()
		f.pending[id] = &pendingOpen{}
		f.mu.Unlock()
		b := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize)
		ip := header.IPv4(b)
		ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(b)), TTL: 64, Protocol: uint8(gtcp.ProtocolNumber), SrcAddr: src, DstAddr: dst})
		ip.SetChecksum(^ip.CalculateChecksum())
		h := header.TCP(b[20:])
		h.Encode(&header.TCPFields{SrcPort: 40000, DstPort: 443, SeqNum: 1000, DataOffset: 20, Flags: header.TCPFlagSyn, WindowSize: 65535})
		h.SetChecksum(^checksum.Checksum(h, header.PseudoHeaderChecksum(gtcp.ProtocolNumber, src, dst, uint16(len(h)))))
		p := gv.NewPacketBuffer(gv.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
		p.NetworkHeader().Consume(20)
		p.TransportHeader().Consume(20)
		p.NetworkProtocolNumber = header.IPv4ProtocolNumber
		handled := f.Handle(id, p)
		p.DecRef()
		stats := f.SilentStats()
		f.mu.Lock()
		delete(f.pending, id)
		f.mu.Unlock()
		f.Stop()
		s.Close()
		s.Wait()
		f.Wait()
		l.Close()
		if !handled || c.Begun.Load() != 0 {
			t.Fatalf("enabled %t: the duplicate SYN was not answered as a duplicate", enabled)
		}
		if !enabled {
			if stats != nil || f.silent != nil {
				t.Fatalf("diagnostics off, yet recorded: %v", stats)
			}
			continue
		}
		recent := stats["recent"].([]SilentSYN)
		if stats["counts"].(map[string]uint64)["pending"] != 1 || len(recent) != 1 || recent[0].Reason != "pending" ||
			recent[0].Source != "198.18.0.2:40000" || recent[0].Destination != "203.0.113.7:443" || stats["unopened"] != 1 {
			t.Fatalf("diagnostics on: %+v", stats)
		}
	}
}
