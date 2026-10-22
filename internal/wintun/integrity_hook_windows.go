//go:build windows && wintun_integrity

package wintun

import "sync/atomic"

// Only the explicitly tagged diagnostic binary can observe native ring memory.
// The callback is synchronous and must not retain either borrowed slice.
const integrityHooksEnabled = true

type integrityRingObserver struct {
	observe func(stage string, native, copied []byte)
}

var integrityRingHook atomic.Pointer[integrityRingObserver]

type integrityRingPacket struct{ native, source []byte }
type integrityRingBatch struct{ packets []integrityRingPacket }

func (b *integrityRingBatch) add(native, source []byte) {
	if integrityRingHook.Load() != nil {
		b.packets = append(b.packets, integrityRingPacket{native, source})
	}
}

func (b *integrityRingBatch) publish() {
	// Check after ALL copies, just before the single tail publication. A later
	// copy overwriting an earlier reservation must not be blamed on the driver.
	for _, p := range b.packets {
		observeRingSend(p.native, p.source)
	}
	clear(b.packets)
	b.packets = nil
}

func observeRingReceive(native, copied []byte) {
	if h := integrityRingHook.Load(); h != nil {
		h.observe("ours_receive", native, copied)
	}
}

func observeRingSend(native, source []byte) {
	if h := integrityRingHook.Load(); h != nil {
		h.observe("ours_send", native, source)
	}
}
