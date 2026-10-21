//go:build windows

package udp

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
	"github.com/AyoubAchour/net-switch/internal/winclock"
)

type readErrorDatagram struct {
	*readyDatagram
	attempts atomic.Int32
}

func (s *readErrorDatagram) TryReadFrom(b []byte) (int, netip.AddrPort, error) {
	if s.attempts.Add(1) <= 4 {
		return 0, netip.AddrPort{}, errors.New("fixture recoverable receive error")
	}
	return s.readyDatagram.TryReadFrom(b)
}

func TestReadyUDPReadErrorBackoffMakesProgressUnderWindowsClock(t *testing.T) {
	// The shared backoff uses Go's monotonic clock both for readAfter and
	// its runtime timer. On ARM this is coarse. With no new app packet or
	// readiness callback, only those timers can make the queued reply progress.
	c := &testfake.Controller{}
	socket := &readErrorDatagram{readyDatagram: &readyDatagram{socket: newSocket()}}
	socket.in <- wire{[]byte("after errors"), dest}
	d := testfake.Dialer{UDPFunc: func(context.Context, string, bool) (platform.UDPConn, error) { return socket, nil }}
	link := ns.NewLink()
	defer link.Close()
	n := New(context.Background(), nil, c, &testfake.Owners{Value: owner}, nil, d, link, 9000)
	defer n.Close()
	precise, coarse := winclock.Now(), time.Now()
	send(n, dest, []byte("open"))
	await(t, socket.out)
	waitReplyState(t, func() bool { return link.Queued() == 1 && socket.attempts.Load() >= 6 })
	// receive can deliver its initial scheduling hint after the setup worker's
	// hint, so one additional non-consuming TryRead is legitimate.
	if n.ReadErrors.Load() != 4 || socket.attempts.Load() > 7 || c.Closed.Load() != 0 {
		t.Fatalf("receive errors spun, stalled or killed mapping: errors=%d attempts=%d closed=%d",
			n.ReadErrors.Load(), socket.attempts.Load(), c.Closed.Load())
	}
	var output [1]ns.OutputPacket
	if link.ReadOwnedBatch(context.Background(), output[:]) != 1 {
		t.Fatal("queued reply disappeared")
	}
	if !bytes.Equal(output[0].Bytes, packet.UDP(dest, local, []byte("after errors"))) {
		t.Fatal("timer-only recovery changed the reply")
	}
	output[0].Release()
	if c.Reply.Load() != 0 || c.ReadBytes.Load() != 0 {
		t.Fatal("receive retry retained reply storage")
	}
	t.Logf("four timer-only receive retries and exact reply completed: QPC=%s Go=%s; Try calls=%d, zero retained bytes",
		winclock.Since(precise), time.Since(coarse), socket.attempts.Load())
}
