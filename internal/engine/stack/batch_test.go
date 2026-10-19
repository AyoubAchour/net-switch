package stack_test

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
)

func TestLinkBatchFIFOAndLonePacket(t *testing.T) {
	l := ns.NewLink()
	defer l.Close()
	packets := make([][]byte, 37)
	for round := 0; round < 3; round++ {
		for i := 0; i < ns.QueuePackets; i++ {
			p := make([]byte, 4)
			binary.LittleEndian.PutUint32(p, uint32(i+round*ns.QueuePackets))
			if !l.Send(p) {
				t.Fatal("queue filled before capacity")
			}
		}
		if l.Send([]byte{1}) {
			t.Fatal("full queue did not drop")
		}
		for received := 0; received < ns.QueuePackets; {
			want := min(len(packets), ns.QueuePackets-received)
			n := l.ReadBatch(context.Background(), packets)
			if n != want {
				t.Fatalf("batch %d, want %d", n, want)
			}
			for _, p := range packets[:n] {
				if binary.LittleEndian.Uint32(p) != uint32(received+round*ns.QueuePackets) {
					t.Fatal("packet order changed")
				}
				received++
			}
		}
	}
	if l.Dropped.Load() != 3 {
		t.Fatal("drop accounting changed")
	}
	if !l.Send([]byte("one")) {
		t.Fatal("send")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if n := l.ReadBatch(ctx, packets); n != 1 || string(packets[0]) != "one" {
		t.Fatal("batch waited for more than one packet")
	}
	cancel()
	if n := l.ReadBatch(ctx, packets); n != 0 {
		t.Fatal("cancelled empty read returned data")
	}
	l.Close()
	if n := l.ReadBatch(context.Background(), packets); n != 0 {
		t.Fatal("closed read did not finish")
	}
}
