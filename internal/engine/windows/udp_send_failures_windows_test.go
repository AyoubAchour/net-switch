//go:build windows

package winengine

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"golang.org/x/sys/windows"
)

// Only errors that become an invented ICMP unreachable are recorded, with
// their Winsock code, so the next unexplained unreachable names its cause.
func TestUDPSendFailuresRecordOnlyUnreachableCauses(t *testing.T) {
	destination := netip.MustParseAddrPort("198.19.128.2:26000")
	before := udpSendFailureStats()["count"].(uint64)
	noteUDPSendFailure("test", destination, nil)
	noteUDPSendFailure("test", destination, platform.ErrWouldBlock)
	noteUDPSendFailure("test", destination, platform.ErrDatagramDropped)
	noteUDPSendFailure("test", destination, &platform.TooBig{MTU: 1400})
	noteUDPSendFailure("test", destination, fmt.Errorf("wsasendto: %w", windows.WSAECONNRESET))
	stats := udpSendFailureStats()
	if got := stats["count"].(uint64) - before; got != 1 {
		t.Fatalf("recorded %d failures, want 1", got)
	}
	recent := stats["recent"].([]udpSendFailure)
	last := recent[len(recent)-1]
	if last.Errno != uint32(windows.WSAECONNRESET) || last.Destination != destination.String() || last.Path != "test" {
		t.Fatalf("last failure %+v", last)
	}
}
