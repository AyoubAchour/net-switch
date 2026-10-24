package lifecycle_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func primaryInterface(t *testing.T) (string, string) {
	t.Helper()
	route, err := net.Dial("udp4", "192.0.2.1:9")
	if err != nil {
		t.Fatal(err)
	}
	ip := route.LocalAddr().(*net.UDPAddr).IP
	route.Close() // no datagram was sent
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, nic := range interfaces {
		addrs, _ := nic.Addrs()
		for _, address := range addrs {
			candidate, _, err := net.ParseCIDR(address.String())
			if err == nil && candidate.Equal(ip) {
				return nic.Name, ip.String()
			}
		}
	}
	t.Fatal("no interface for default egress")
	return "", ""
}
func echoServer(t *testing.T, address string) string {
	t.Helper()
	listener, err := net.Listen("tcp4", net.JoinHostPort(address, "0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	return listener.Addr().String()
}

// apiDialer carries the suite's own HTTP requests to Control. On Linux, Control
// runs inside the TUN fixture's network namespace, so the fixture's relay
// dials for us; on Windows it stays nil and the loopback address is direct.
var apiDialer func(context.Context, string, string) (net.Conn, error)

func apiClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{DisableKeepAlives: true}
	if apiDialer != nil {
		transport.DialContext = apiDialer
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}

// routedStream opens a connection to the fixture's target through the native
// engine: on Windows through the TestISP adapter, on Linux through the
// namespace relay. fixture.exchange proves bytes flow both ways.
func routedStream(t *testing.T, ctx context.Context, fixture tunFixture) net.Conn {
	t.Helper()
	conn, err := fixture.dial(ctx, "tcp4", fixture.target)
	if err != nil {
		t.Fatal("routed stream", err)
	}
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	return conn
}

// directTraffic is the fail-open check: the same target must work with no
// engine running, over the fixture's own route.
func directTraffic(t *testing.T, ctx context.Context, fixture tunFixture) {
	t.Helper()
	conn, err := fixture.dial(ctx, "tcp4", fixture.target)
	if err != nil {
		t.Fatal("direct connection unavailable after engine failure", err)
	}
	defer conn.Close()
	fixture.exchange(t, conn)
}
func checkEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	message := []byte(fmt.Sprintf("lifecycle-%d\n", time.Now().UnixNano()))
	if _, err := conn.Write(message); err != nil {
		t.Fatal("stream write:", err)
	}
	reply := make([]byte, len(message))
	if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != string(message) {
		t.Fatal("stream was interrupted", err)
	}
}
func expectClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var b [1]byte
	_, err := conn.Read(b[:])
	if err == nil {
		t.Fatal("old engine still forwards")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("old stream was not closed when the engine died")
	}
}
