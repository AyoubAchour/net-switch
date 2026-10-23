//go:build lifecycle_test || acceptance

package testproxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
)

type addressed struct {
	net.Conn
	local, remote string
}

func (c addressed) LocalAddr() net.Addr {
	return net.TCPAddrFromAddrPort(netip.MustParseAddrPort(c.local))
}
func (c addressed) RemoteAddr() net.Addr {
	return net.TCPAddrFromAddrPort(netip.MustParseAddrPort(c.remote))
}

type pipeListener struct {
	incoming chan net.Conn
	done     chan struct{}
	once     sync.Once
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.incoming:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *pipeListener) Close() error { l.once.Do(func() { close(l.done) }); return nil }
func (*pipeListener) Addr() net.Addr {
	return net.TCPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:9000"))
}
func (l *pipeListener) connect(t *testing.T) net.Conn {
	t.Helper()
	a, b := net.Pipe()
	a.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { a.Close() })
	select {
	case l.incoming <- addressed{b, "127.0.0.1:9000", "127.0.0.1:20000"}:
	case <-time.After(time.Second):
		t.Fatal("accept blocked")
	}
	return a
}

func fixture(t *testing.T, blocked bool) (*Server, *pipeListener, *flows.Table, *atomic.Int64) {
	t.Helper()
	table := flows.New(flows.Defaults(), nil)
	config := policy.Config{Lines: []platform.Line{{ID: "A"}, {ID: "B"}}, AppLines: map[string]string{"test-app": "B"}, Lanes: map[string]string{"B": "A"}}
	if blocked {
		config.Lanes["B"] = "B"
		config.Blocked = []string{"B"}
	}
	if _, err := table.Apply(policy.Revision{N: 1, Config: config, Hash: policy.Hash(config)}); err != nil {
		t.Fatal(err)
	}
	l := &pipeListener{incoming: make(chan net.Conn), done: make(chan struct{})}
	dials := &atomic.Int64{}
	s, err := New(context.Background(), Options{Address: "127.0.0.1:0", Table: table, Owners: &testfake.Owners{Value: platform.Owner{AppID: "test-app"}},
		Listen: func(string, string) (net.Listener, error) { return l, nil },
		Dial: func(_ context.Context, line string, dst netip.AddrPort) (net.Conn, error) {
			dials.Add(1)
			if line != "A" || dst.String() != "192.0.2.1:443" {
				return nil, errors.New("wrong policy or destination")
			}
			a, b := net.Pipe()
			go func() { defer b.Close(); io.Copy(b, b) }()
			return addressed{a, "192.0.2.2:21000", dst.String()}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, l, table, dials
}

func TestProxyUsesPolicyAndAccountsCoalescedPayload(t *testing.T) {
	for _, socks := range []bool{false, true} {
		s, l, table, dials := fixture(t, false)
		c := l.connect(t)
		payload := []byte("hello")
		request := []byte("CONNECT 192.0.2.1:443 HTTP/1.1\r\nHost: 192.0.2.1:443\r\n\r\n")
		if socks {
			request = []byte{5, 1, 0, 5, 1, 0, 1, 192, 0, 2, 1, 1, 187}
		}
		if _, err := c.Write(append(request, payload...)); err != nil {
			t.Fatal(err)
		}
		r := bufio.NewReader(c)
		if socks {
			var reply [12]byte
			if _, err := io.ReadFull(r, reply[:]); err != nil || reply[1] != 0 || reply[3] != 0 {
				t.Fatal(reply, err)
			}
		} else {
			line, err := r.ReadString('\n')
			if err != nil || !strings.Contains(line, "200") {
				t.Fatal(line, err)
			}
			if _, err := r.ReadString('\n'); err != nil {
				t.Fatal(err)
			}
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(r, got); err != nil || !bytes.Equal(got, payload) {
			t.Fatal(string(got), err)
		}
		c.Close()
		s.Close()
		if dials.Load() != 1 || table.Stats().Flows != 0 || table.Totals().Apps["test-app"] != (flows.Bytes{Up: 5, Down: 5}) || table.Totals().Lines["A"] != (flows.Bytes{Up: 5, Down: 5}) {
			t.Fatal(dials.Load(), table.Stats(), table.Totals())
		}
	}
}

func TestProxyRefusesBlockedPolicyBeforeDial(t *testing.T) {
	s, l, table, dials := fixture(t, true)
	c := l.connect(t)
	if _, err := io.WriteString(c, "CONNECT 192.0.2.1:443 HTTP/1.1\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || !strings.Contains(line, "403") {
		t.Fatal(line, err)
	}
	c.Close()
	s.Close()
	if dials.Load() != 0 || table.Stats().Flows != 0 {
		t.Fatal("denied flow dialed or leaked")
	}
}

func TestProxyBoundedBeforeHandshakeAndLoopbackOnly(t *testing.T) {
	for _, address := range []string{"0.0.0.0:0", "[::]:0", "192.0.2.1:1", "localhost:0"} {
		if _, err := New(context.Background(), Options{Address: address, Listen: func(string, string) (net.Listener, error) { t.Fatal("non-loopback listen"); return nil, nil }}); err == nil {
			t.Fatal(address)
		}
	}
	s, l, table, dials := fixture(t, false)
	for range MaxConnections {
		l.connect(t)
	}
	until := time.Now().Add(time.Second)
	for s.Status().Connections != MaxConnections && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if s.Status().Connections != MaxConnections {
		t.Fatal("capacity fixture not held")
	}
	extra := l.connect(t)
	var b [1]byte
	if n, err := extra.Read(b[:]); n != 0 || err != io.EOF {
		t.Fatal("overflow was not immediately closed", n, err)
	}
	if _, err := table.Page(""); err != nil {
		t.Fatal("stalled handshakes blocked control", err)
	}
	s.Close()
	if s.Status().Connections != 0 || dials.Load() != 0 {
		t.Fatal("pending handshakes leaked or dialed")
	}
	for _, dst := range []string{"127.0.0.1:9000", "[::1]:9000", "0.0.0.0:1", "bad target:2", "192.0.2.1:0"} {
		if _, err := destination(context.Background(), dst); err == nil {
			t.Fatal("invalid/self destination", dst)
		}
	}
}

type memoryConn struct {
	*bytes.Reader
	output bytes.Buffer
}

func (c *memoryConn) Write(b []byte) (int, error)    { return c.output.Write(b) }
func (*memoryConn) Close() error                     { return nil }
func (*memoryConn) LocalAddr() net.Addr              { return nil }
func (*memoryConn) RemoteAddr() net.Addr             { return nil }
func (*memoryConn) SetDeadline(time.Time) error      { return nil }
func (*memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (*memoryConn) SetWriteDeadline(time.Time) error { return nil }

func FuzzProxyHandshake(f *testing.F) {
	f.Add([]byte("CONNECT 192.0.2.1:443 HTTP/1.1\r\n\r\n"))
	f.Add([]byte{5, 1, 0, 5, 1, 0, 1, 192, 0, 2, 1, 1, 187})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) == 0 || len(b) > HeaderBytes+512 {
			return
		}
		c := &memoryConn{Reader: bytes.NewReader(b)}
		handshake(c, bufio.NewReaderSize(c, 4096), b[0] == 5)
		if c.output.Len() > 32 {
			t.Fatal("unbounded handshake reply")
		}
	})
}
