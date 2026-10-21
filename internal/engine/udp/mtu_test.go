package udp

import (
	"bytes"
	"encoding/binary"
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
	payload := make([]byte, 9000-28+1)
	for i := range payload {
		payload[i] = byte(i)
	}
	s.in <- wire{payload, dest}
	joined := make([]byte, len(payload)+8)
	for range 2 {
		fragment := await(t, out)
		offset := int(binary.BigEndian.Uint16(fragment[6:])&0x1fff) * 8
		copy(joined[offset:], fragment[20:])
	}
	if !bytes.Equal(joined[8:], payload) || n.Oversize.Load() != 0 {
		t.Fatal("representable large reply was dropped or corrupted")
	}
	s.in <- wire{make([]byte, 65508), dest}
	s.in <- wire{[]byte("still open"), dest}
	raw := await(t, out)
	_, _, _, off, total, ok := packet.IPHeader(raw, false)
	if !ok || string(raw[off+8:total]) != "still open" || n.Oversize.Load() != 1 {
		t.Fatal("unrepresentable reply was not dropped and counted")
	}
}
