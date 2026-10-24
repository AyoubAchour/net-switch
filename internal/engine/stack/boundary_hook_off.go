//go:build !wintun_boundaries

package stack

import gv "gvisor.dev/gvisor/pkg/tcpip/stack"

const boundaryHooksEnabled = false

func observeBoundaryPacket(*gv.PacketBuffer) {}
