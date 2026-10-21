//go:build windows

package winengine

import (
	"net"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// Winsock's stale answer for a duplicate (unbound while its source is bound)
// was seen on hosted x64 only occasionally. Make it deterministic: the
// duplicate step must discard stale duplicates, keep a good one, and give up
// with an error after its bounded attempts, never returning a stale socket.
func TestStaleWinsockDuplicateIsDiscarded(t *testing.T) {
	hosted(t)
	original := duplicateName
	defer func() { duplicateName = original }()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	duplicate := func(staleAnswers int) (windows.Handle, error) {
		file, err := conn.File()
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		owner, err := ownGoDescriptor(file, "stale duplicate test File")
		if err != nil {
			t.Fatal(err)
		}
		defer owner.CloseGo("stale duplicate test File close", file.Close)
		calls := 0
		duplicateName = func(h windows.Handle) (windows.Sockaddr, error) {
			calls++
			if calls <= staleAnswers {
				return nil, windows.WSAEINVAL // what Winsock answered for the stale duplicate
			}
			return original(h)
		}
		h, err := duplicateForReadiness(file, owner)
		if err != nil {
			return 0, err
		}
		defer h.SocketClose("stale duplicate test close")
		value := h.Handle("stale duplicate test name")
		name, err := windows.Getsockname(value)
		if err != nil || name.(*windows.SockaddrInet4).Port != conn.LocalAddr().(*net.UDPAddr).Port {
			t.Fatalf("kept duplicate %#x has name %#v: %v", value, name, err)
		}
		return value, nil
	}
	before := staleDuplicates.Load()
	if _, err := duplicate(2); err != nil {
		t.Fatalf("two stale answers then a good one: %v", err)
	}
	if got := staleDuplicates.Load() - before; got != 2 {
		t.Fatalf("discarded %d stale duplicates, want 2", got)
	}
	before = staleDuplicates.Load()
	_, err = duplicate(staleDuplicateAttempts)
	if err == nil || !strings.Contains(err.Error(), "after 3 attempts") {
		t.Fatalf("stale on every attempt returned %v", err)
	}
	if got := staleDuplicates.Load() - before; got != staleDuplicateAttempts {
		t.Fatalf("discarded %d stale duplicates, want %d", got, staleDuplicateAttempts)
	}
}
