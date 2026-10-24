//go:build windows && wintun_boundaries

package wintun

import "sync/atomic"

const wordBoundaryHooksEnabled = true

type wordRingObserver struct {
	inspect func(stage string, packet []byte, slot int64, batch uint64, index int)
}

var wordRingHook atomic.Pointer[wordRingObserver]
var wordRingBatchID atomic.Uint64

func nextWordReadBatch() uint64 { return wordRingBatchID.Add(1) }
func observeWordRingRead(p []byte, slot uint32, batch uint64, index int) {
	if h := wordRingHook.Load(); h != nil {
		h.inspect("ring_ingress", p, int64(slot), batch, index)
	}
}

type wordBoundarySlot struct {
	packet []byte
	slot   uint32
	index  int
}
type wordBoundaryBatch struct {
	observer *wordRingObserver
	id       uint64
	count    int
	slots    [64]wordBoundarySlot
}

func newWordBoundaryBatch() wordBoundaryBatch {
	b := wordBoundaryBatch{observer: wordRingHook.Load()}
	if b.observer != nil {
		b.id = wordRingBatchID.Add(1)
	}
	return b
}
func (b *wordBoundaryBatch) add(p []byte, slot uint32, index int) {
	if b.observer == nil {
		return
	}
	if b.count == len(b.slots) {
		b.observer.inspect("batch_overflow", nil, int64(slot), b.id, index)
		return
	}
	b.slots[b.count] = wordBoundarySlot{p, slot, index}
	b.count++
}
func (b *wordBoundaryBatch) publish() {
	if b.observer == nil {
		return
	}
	// Re-read the native slots after every copy, before publishing Tail.
	for _, s := range b.slots[:b.count] {
		b.observer.inspect("ring_publish", s.packet, int64(s.slot), b.id, s.index)
	}
}
