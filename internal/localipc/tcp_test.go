package localipc

import (
	"net"
	"testing"
)

func TestTCPOwnerMatchesLiveClientTuple(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	user, err := TCPOwner(server.RemoteAddr().(*net.TCPAddr), server.LocalAddr().(*net.TCPAddr))
	if err != nil || user == "" {
		t.Fatal("OS could not identify live loopback client", user, err)
	}
	wrong := *server.RemoteAddr().(*net.TCPAddr)
	wrong.Port = 0
	if _, err := TCPOwner(&wrong, server.LocalAddr().(*net.TCPAddr)); err == nil {
		t.Fatal("unrelated client tuple accepted")
	}
}
