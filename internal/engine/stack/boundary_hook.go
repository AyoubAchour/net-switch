//go:build wintun_boundaries

package stack

import (
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
	"sync/atomic"
)

const boundaryHooksEnabled = true

type packetBoundaryObserver struct{ inspect func(*gv.PacketBuffer) }

var wordPacketHook atomic.Pointer[packetBoundaryObserver]

// InstallBoundaryObserver borrows packets synchronously, before queue copying.
// The observer must not modify, release or retain any view or packet reference.
func InstallBoundaryObserver(inspect func(*gv.PacketBuffer)) (func(), bool) {
	h := &packetBoundaryObserver{inspect: inspect}
	if !wordPacketHook.CompareAndSwap(nil, h) {
		return nil, false
	}
	return func() { wordPacketHook.CompareAndSwap(h, nil) }, true
}

func observeBoundaryPacket(p *gv.PacketBuffer) {
	if h := wordPacketHook.Load(); h != nil {
		h.inspect(p)
	}
}
