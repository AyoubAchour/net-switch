package stack

import (
	"context"
	"runtime"
	"testing"
)

func TestOutputCacheSurvivesGCAndEndsWithLink(t *testing.T) {
	l := NewLink()
	defer l.Close()
	var batch [1]OutputPacket
	for _, size := range []int{64, MTU} {
		data := make([]byte, size)
		data[0] = 73
		if !l.Send(data) || l.ReadOwnedBatch(context.Background(), batch[:]) != 1 {
			t.Fatal("could not establish a real output buffer")
		}
		original := &batch[0].Bytes[0]
		batch[0].Release()
		// sync.Pool's victim cache is dropped by the second collection.
		runtime.GC()
		runtime.GC()
		if !l.Send(data) || l.ReadOwnedBatch(context.Background(), batch[:]) != 1 || &batch[0].Bytes[0] != original {
			t.Fatal("GC discarded reusable output storage")
		}
		batch[0].Release()
	}
	if l.buffers.smallCount != 1 || l.buffers.largeCount != 1 {
		t.Fatal("both cached buffers must exist before checking cleanup")
	}
	if !l.Send([]byte{91}) || l.ReadOwnedBatch(context.Background(), batch[:]) != 1 {
		t.Fatal("could not keep one writer loan alive across close")
	}
	l.Close()
	if l.buffers.smallCount != 0 || l.buffers.largeCount != 0 {
		t.Fatal("closing the link retained cached buffers")
	}
	if batch[0].Bytes[0] != 91 {
		t.Fatal("close invalidated a writer's owned packet")
	}
	batch[0].Release()
	if l.buffers.smallCount != 0 {
		t.Fatal("late writer release repopulated the closed cache")
	}
}

func TestOutputCacheRetentionIsBounded(t *testing.T) {
	l := NewLink()
	defer l.Close()
	loans := make([]OutputPacket, QueuePackets+128)
	data := make([]byte, MTU)
	for i := range loans {
		if !l.Send(data) || l.ReadOwnedBatch(context.Background(), loans[i:i+1]) != 1 {
			t.Fatal("could not borrow output storage")
		}
	}
	for i := range loans {
		loans[i].Release()
	}
	if l.buffers.largeCount != QueuePackets+64 {
		t.Fatalf("cached %d buffers after %d outstanding loans", l.buffers.largeCount, len(loans))
	}
}
