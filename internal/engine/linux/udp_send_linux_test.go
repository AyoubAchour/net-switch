//go:build linux

package linux

import (
	"errors"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"golang.org/x/sys/unix"
	"testing"
)

func TestUDPSendRetriesPreviousDestinationErrorOnce(t *testing.T) {
	calls, drains := 0, 0
	err := sendDatagram(func() error {
		calls++
		if calls == 1 {
			return unix.ECONNREFUSED
		}
		return nil
	}, func() { drains++ })
	if err != nil || calls != 2 || drains != 1 {
		t.Fatalf("send B after error A: calls=%d drains=%d err=%v", calls, drains, err)
	}
	calls, drains = 0, 0
	err = sendDatagram(func() error { calls++; return unix.ECONNREFUSED }, func() { drains++ })
	if !errors.Is(err, platform.ErrDatagramDropped) || calls != 2 || drains != 2 {
		t.Fatal("retry was unbounded or falsely attributed")
	}
}
func TestUDPNoBuffersIsCountableSilentDrop(t *testing.T) {
	calls := 0
	err := sendDatagram(func() error { calls++; return unix.ENOBUFS }, func() { t.Fatal("local buffer drop drained remote errors") })
	if !errors.Is(err, platform.ErrDatagramDropped) || calls != 1 {
		t.Fatal("ENOBUFS became unreachable or was retried")
	}
}
