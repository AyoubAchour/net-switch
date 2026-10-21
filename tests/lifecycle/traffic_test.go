package lifecycle_test

import (
	"bufio"
	"encoding/json"
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
func proxyStream(t *testing.T, url, token, target string) net.Conn {
	t.Helper()
	status, b := api(t, url, token, "GET", "/api/state", "")
	if status != 200 {
		t.Fatal("state before traffic:", status)
	}
	var state struct {
		Routing struct {
			Port *int `json:"proxyPort"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(b, &state); err != nil || state.Routing.Port == nil {
		t.Fatal("running proxy has no port", err)
	}
	return proxyStreamPort(t, *state.Routing.Port, target)
}
func proxyStreamPort(t *testing.T, port int, target string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "CONNECT"})
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if response.StatusCode != 200 {
		conn.Close()
		t.Fatal("adapter CONNECT:", response.Status)
	}
	return conn
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
func directEcho(t *testing.T, address string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", address, 5*time.Second)
	if err != nil {
		t.Fatal("direct connection unavailable after engine failure", err)
	}
	defer conn.Close()
	checkEcho(t, conn)
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
