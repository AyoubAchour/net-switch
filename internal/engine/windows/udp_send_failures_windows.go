//go:build windows

package winengine

import (
	"errors"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

// UDP sends that fail with anything but would-block, a counted local drop or
// too-big make the NAT send the app an ICMP port unreachable for that
// datagram, without a refusal count. Windows acceptance on ARM64 (run
// 39621333715) showed exactly that unreachable 1 ms after a request, and
// nothing recorded which Winsock error caused it. Record each such error.
type udpSendFailure struct {
	At          time.Time `json:"at"`
	Path        string    `json:"path"`
	Destination string    `json:"destination"`
	Error       string    `json:"error"`
	Errno       uint32    `json:"errno,omitempty"`
}

var udpSendFailures struct {
	sync.Mutex
	count  uint64
	byErr  map[string]uint64
	recent [8]udpSendFailure
	next   int
}

func noteUDPSendFailure(path string, destination netip.AddrPort, err error) {
	var tooBig *platform.TooBig
	if err == nil || errors.Is(err, platform.ErrWouldBlock) || errors.Is(err, platform.ErrDatagramDropped) || errors.As(err, &tooBig) {
		return
	}
	record := udpSendFailure{At: time.Now(), Path: path, Destination: destination.String(), Error: err.Error()}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		record.Errno = uint32(errno)
	}
	udpSendFailures.Lock()
	defer udpSendFailures.Unlock()
	udpSendFailures.count++
	if udpSendFailures.byErr == nil {
		udpSendFailures.byErr = make(map[string]uint64)
	}
	udpSendFailures.byErr[record.Error]++
	udpSendFailures.recent[udpSendFailures.next%len(udpSendFailures.recent)] = record
	udpSendFailures.next++
}

func udpSendFailureStats() map[string]any {
	udpSendFailures.Lock()
	defer udpSendFailures.Unlock()
	recent := make([]udpSendFailure, 0, len(udpSendFailures.recent))
	for i := max(0, udpSendFailures.next-len(udpSendFailures.recent)); i < udpSendFailures.next; i++ {
		recent = append(recent, udpSendFailures.recent[i%len(udpSendFailures.recent)])
	}
	byErr := make(map[string]uint64, len(udpSendFailures.byErr))
	for key, value := range udpSendFailures.byErr {
		byErr[key] = value
	}
	return map[string]any{"count": udpSendFailures.count, "byError": byErr, "recent": recent}
}
