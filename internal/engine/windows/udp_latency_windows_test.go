//go:build windows

package winengine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/winclock"
)

// Hold allocation constant and vary how many idle watches remain read-armed.
// The real NAT always rearms idle reads; allocation-only fixtures did not.
// This diagnoses the backend. The real-engine harness gates EVERY held flow.
func TestReadyUDPArmedIdleLatency(t *testing.T) {
	hosted(t)
	if os.Getenv("NETSWITCH_UDP_READINESS_GATE") != "1" {
		t.Skip("large native readiness measurement runs in a focused hosted job")
	}
	t.Setenv("NETSWITCH_ENGINE_TEST_TRACE", "1")
	const count, active, rounds = 8000, 32, 8
	pool, err := newUDPReadiness(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pool.close(); err != nil {
			t.Error(err)
		}
	})
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 3)})
	if err != nil {
		t.Fatal(err)
	}
	peerDone := make(chan struct{})
	var peerErrors atomic.Uint64
	go func() {
		defer close(peerDone)
		var b [64]byte
		for {
			n, from, err := peer.ReadFromUDPAddrPort(b[:])
			if err != nil {
				return
			}
			if n, err := peer.WriteToUDPAddrPort(b[:n], from); err != nil || n == 0 {
				peerErrors.Add(1)
			}
		}
	}()
	defer func() { peer.Close(); <-peerDone }()
	destination := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	sockets := make([]*udpSocket, count)
	watches := make([]platform.Readiness, count)
	wakes := make([]chan struct{}, active)
	var unexpected atomic.Uint64
	line := loopbackLine(t)
	for i := range sockets {
		s, err := openUDP(line, netip.MustParseAddrPort("127.0.0.2:0"), pool)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := s.Close(); err != nil {
				t.Error(err)
			}
		})
		var wake chan struct{}
		if i < active {
			wake = make(chan struct{}, 1)
			wakes[i] = wake
		}
		watch, err := s.Watch(func() {
			if wake == nil {
				unexpected.Add(1)
				return
			}
			select {
			case wake <- struct{}{}:
			default:
				unexpected.Add(1)
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		sockets[i], watches[i] = s, watch
	}
	previous := 0
	for _, armed := range []int{32, 256, 1024, 4096, count} {
		for i := previous; i < armed; i++ {
			if err := watches[i].Arm(true, false); err != nil {
				t.Fatal(err)
			}
		}
		previous = armed
		before := pool.stats()
		if before["registered"] != count || before["armed"] != armed {
			t.Fatalf("idle precondition: %v", before)
		}
		samples := make([]int64, active*rounds)
		failures := make(chan error, active*rounds)
		started := winclock.Now()
		for round := range rounds {
			var workers sync.WaitGroup
			for i := range active {
				workers.Go(func() {
					payload := []byte(fmt.Sprintf("held=%d round=%d socket=%d", armed, round, i))
					start := winclock.Now()
					if n, err := sockets[i].TryWriteTo(payload, destination, false); err != nil || n != len(payload) {
						failures <- fmt.Errorf("write socket %d: %d %v", i, n, err)
						return
					}
					timer := time.NewTimer(2 * time.Second)
					select {
					case <-wakes[i]:
						timer.Stop()
					case <-timer.C:
						failures <- fmt.Errorf("socket %d lost readiness", i)
						return
					}
					var b [64]byte
					n, from, err := sockets[i].TryReadFrom(b[:])
					if err != nil || from != destination || !bytes.Equal(b[:n], payload) {
						failures <- fmt.Errorf("read socket %d: %d %s %v", i, n, from, err)
						return
					}
					samples[round*active+i] = int64(winclock.Since(start))
					if err := watches[i].Arm(true, false); err != nil {
						failures <- err
					}
				})
			}
			workers.Wait()
			if len(failures) != 0 {
				break
			}
		}
		elapsed := winclock.Since(started)
		after := pool.stats()
		close(failures)
		var failuresText []string
		for err := range failures {
			failuresText = append(failuresText, err.Error())
		}
		slices.Sort(samples)
		memory, memoryErr := processMemory()
		value, _ := json.Marshal(map[string]any{"armed": armed, "held": count, "active": active,
			"rounds": rounds, "samples": len(samples), "p99MS": float64(samples[(len(samples)*99+99)/100-1]) / 1e6,
			"maxMS": float64(samples[len(samples)-1]) / 1e6, "elapsedMS": float64(elapsed) / 1e6,
			"failures": failuresText, "before": before, "after": after, "goroutines": runtime.NumGoroutine(),
			"systemResources": systemResources(), "processMemory": memory, "memoryError": errorText(memoryErr)})
		t.Logf("WINDOWS UDP ARMED READINESS %s", value)
		if len(failuresText) != 0 || peerErrors.Load() != 0 || unexpected.Load() != 0 || after["armed"] != armed {
			t.Fatalf("readiness oracles failed: failures=%v peer=%d unexpected=%d armed=%v/%d", failuresText, peerErrors.Load(), unexpected.Load(), after["armed"], armed)
		}
	}
}
