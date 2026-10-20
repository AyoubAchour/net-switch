package stack

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/packet"
)

func TestBulkOutputLeavesReservedSlotsForDNSAndControl(t *testing.T) {
	l := NewLink()
	defer l.Close()
	bulk := make([]byte, 1500)
	bulk[0], bulk[9], bulk[32], bulk[33] = 0x45, 6, 0x50, 0x18
	for range QueuePackets {
		l.Send(bulk)
	}
	if l.Queued() != QueuePackets-ReservedControlPackets || l.DropCounts()["tcpData"] != ReservedControlPackets {
		t.Fatal("bulk load did not exhaust only the unreserved slots")
	}
	dns := packet.UDP(netip.MustParseAddrPort("203.0.113.1:53"), netip.MustParseAddrPort("198.18.0.1:40000"), make([]byte, 2048))
	for i := range ReservedControlPackets {
		binary.BigEndian.PutUint16(dns[len(dns)-2:], uint16(i))
		if !l.Send(dns) {
			t.Fatal("bulk download dropped a DNS reply")
		}
	}
	if l.Queued() != QueuePackets || l.DropCounts()["udp"] != 0 {
		t.Fatal("reserved DNS slots missing or total queue bound changed")
	}
	if l.Send(dns) || l.DropCounts()["udp"] != 1 || l.Dropped.Load() != ReservedControlPackets+1 {
		t.Fatal("full control queue did not drop without blocking or classify its drop")
	}
	for range QueuePackets {
		if l.Read(context.Background()) == nil {
			t.Fatal("queue lost a previously accepted packet")
		}
	}
}
