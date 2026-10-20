//go:build windows

package winengine

import (
	"context"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestUDPDualStackSocketIdentity(t *testing.T) {
	hosted(t)
	for _, scenario := range []struct{ name, network, local, remote string }{
		{"ipv6", "udp6", "[::1]:0", "::1"},
		{"mapped-ipv4", "udp4", "127.0.0.1:0", "::ffff:127.0.0.1"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			address, err := net.ResolveUDPAddr(scenario.network, scenario.local)
			if err != nil {
				t.Fatal(err)
			}
			peer, err := net.ListenUDP(scenario.network, address)
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			socket, err := windows.Socket(windows.AF_INET6, windows.SOCK_DGRAM, windows.IPPROTO_UDP)
			if err != nil {
				t.Fatal(err)
			}
			defer windows.Closesocket(socket)
			if err := windows.SetsockoptInt(socket, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY, 0); err != nil {
				t.Fatal(err)
			}
			if err := windows.Bind(socket, &windows.SockaddrInet6{}); err != nil {
				t.Fatal(err)
			}
			destination := &windows.SockaddrInet6{
				Addr: netip.MustParseAddr(scenario.remote).As16(),
				Port: peer.LocalAddr().(*net.UDPAddr).Port,
			}
			if err := windows.Sendto(socket, []byte("native dual-stack UDP"), 0, destination); err != nil {
				t.Fatal(err)
			}
			if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var packet [64]byte
			n, source, err := peer.ReadFromUDPAddrPort(packet[:])
			if err != nil || string(packet[:n]) != "native dual-stack UDP" {
				t.Fatalf("native send did not arrive at its peer: %q %v", packet[:n], err)
			}
			owners := NewOwners()
			owner, lookupErr := owners.UDP(context.Background(), source)
			snapshot, snapshotErr := owners.Snapshot(context.Background(), []netip.AddrPort{source})
			t.Logf("native %s source=%s lookup=%+v err=%v snapshot=%+v err=%v",
				scenario.name, source, owner, lookupErr, snapshot, snapshotErr)
			if lookupErr != nil || owner.PID != uint32(os.Getpid()) || owner.Generation == "" {
				t.Errorf("new socket has no valid UDP identity: %+v %v", owner, lookupErr)
			}
			if snapshotErr != nil || snapshot[source].PID != uint32(os.Getpid()) ||
				snapshot[source].Generation == "" || snapshot[source].Generation != owner.Generation {
				t.Errorf("periodic validation lost the native socket: %+v %v", snapshot, snapshotErr)
			}
		})
	}
}
