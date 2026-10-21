//go:build linux

package app

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/wire"
)

// echoServer answers like the acceptance echo servers: the source it saw,
// then the payload.
func echoServer(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, src, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			_, _ = c.WriteToUDPAddrPort(wire.EchoReply(src, buf[:n]), src)
		}
	}()
	return c
}

func dialAll(t *testing.T, to net.Addr, n int) []net.Conn {
	t.Helper()
	var conns []net.Conn
	for range n {
		c, err := net.Dial("udp", to.String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		conns = append(conns, c)
	}
	return conns
}

func TestSweepEchoesEachRequestedSocketOnceWithinItsConcurrency(t *testing.T) {
	server := echoServer(t)
	silent, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	conns := dialAll(t, server.LocalAddr(), 40)
	conns = append(conns, dialAll(t, silent.LocalAddr(), 1)...)
	// An earlier answer still queued on socket 3 is set aside, not taken for
	// the sweep's own.
	if _, err := conns[3].Write(payload("tok", 0, 3, 0)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	// Socket 5 is not requested, so it must not be sent on.
	var sockets []int
	for i := range conns {
		if i != 5 {
			sockets = append(sockets, i)
		}
	}
	res := sweep(conns, "tok", SweepRequest{Sockets: sockets, Concurrency: 4, EchoTimeoutMS: 300, BudgetMS: 60000})
	if res.MaxInFlight < 1 || res.MaxInFlight > 4 {
		t.Fatalf("max in flight %d, want 1..4", res.MaxInFlight)
	}
	if res.Unsent != 0 || res.Stale != 1 || res.Errors["TIMEOUT"] != 1 || len(res.Errors) != 1 {
		t.Fatalf("unsent %d stale %d errors %v; want 0, 1 and one timeout", res.Unsent, res.Stale, res.Errors)
	}
	for k, i := range sockets {
		local := conns[i].LocalAddr().String()
		switch {
		case i == len(conns)-1:
			if res.RTTMicros[k] != -1 || res.Seen[k] != "" {
				t.Fatalf("silent socket reported rtt %d seen %q", res.RTTMicros[k], res.Seen[k])
			}
		case res.RTTMicros[k] < 0 || res.Seen[k] != local:
			t.Fatalf("socket %d: rtt %d seen %q, want an answer seen from %s", i, res.RTTMicros[k], res.Seen[k], local)
		}
	}
	// Socket 5 got nothing: its next answer is still the one it never asked for.
	_ = conns[5].SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if n, err := conns[5].Read(make([]byte, 64)); err == nil {
		t.Fatalf("unrequested socket 5 was swept (%d bytes)", n)
	}
}

func TestSweepReportsEchoesItCouldNotStartWithinItsBudget(t *testing.T) {
	silent, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	conns := dialAll(t, silent.LocalAddr(), 10)
	sockets := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	res := sweep(conns, "tok", SweepRequest{Sockets: sockets, Concurrency: 1, EchoTimeoutMS: 100, BudgetMS: 1})
	if res.Unsent < 9 || res.Errors["TIMEOUT"] != len(sockets)-res.Unsent {
		t.Fatalf("unsent %d errors %v; want at least 9 unsent and a timeout for each sent", res.Unsent, res.Errors)
	}
	for k := range sockets {
		if res.RTTMicros[k] != -1 {
			t.Fatalf("socket %d reported an answer from a silent server", k)
		}
	}
}
