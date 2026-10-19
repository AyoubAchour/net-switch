package udp

import (
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
)

func TestIPv4ReplyAtTunnelMTU(t *testing.T) {
	n, _, sockets, out, _, _ := setup(t, &testfake.Owners{Value: owner})
	send(n, dest, []byte("open"))
	s := await(t, sockets)
	await(t, s.out)
	s.in <- wire{make([]byte, 9000-28), dest}
	if raw := await(t, out); len(raw) != 9000 {
		t.Fatalf("packet length %d", len(raw))
	}
	s.in <- wire{make([]byte, 9000-28+1), dest}
	s.in <- wire{[]byte("still open"), dest}
	raw := await(t, out)
	_, _, _, off, total, ok := packet.IPHeader(raw, false)
	if !ok || string(raw[off+8:total]) != "still open" || n.Oversize.Load() != 1 {
		t.Fatal("oversize reply was not dropped and counted")
	}
}
