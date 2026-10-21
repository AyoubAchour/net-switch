//go:build windows

package winengine

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"testing"
	"time"
)

// The native control for UDP recovery after the port limit (SYSTEM-DESIGN
// 5.9 open question, 2026-10-21). The engine run releases 512 sessions,
// waits for its reconciliation, reopens 256, and an app's connect has been
// refused with WSAENOBUFS while ports were free. This repeats the same
// sequence with the engine out of the path: app half connected to the peer,
// engine half bound to the line's source with the engine's own bind options,
// filled to the OS limit, then release 512 pairs, wait 1 s, reopen 256 pairs,
// and restore 256 more. Each refusal records its Windows code, the free
// dynamic ports when it happened, and a separate retry 200 ms later.

type udpRecoveryRefusal struct {
	Phase      string `json:"phase"` // reopen or restore
	Half       string `json:"half"`  // app connect or engine bind
	Code       string `json:"code"`
	Errno      uint32 `json:"errno,omitempty"`
	Free       int    `json:"freeAtRefusal"`
	RetryOK    bool   `json:"retryAfter200msOK"`
	RetryCode  string `json:"retryCode,omitempty"`
	RetryErrno uint32 `json:"retryErrno,omitempty"`
}

type udpRecoveryCycle struct {
	Released       int                  `json:"releasedPairs"`
	FreeBefore     int                  `json:"freeBeforeReopen"`
	Reopen         int                  `json:"reopenAttempts"`
	ReopenRefused  int                  `json:"reopenRefused"`
	Restore        int                  `json:"restoreAttempts"`
	RestoreRefused int                  `json:"restoreRefused"`
	Refusals       []udpRecoveryRefusal `json:"refusals,omitempty"`
}

func udpRecoveryCycleCount() int {
	value, err := strconv.Atoi(os.Getenv("NETSWITCH_UDP_RECOVERY_CYCLES"))
	if err != nil || value < 0 {
		return 0
	}
	return value
}

// freeDynamicUDP4 counts IPv4 dynamic UDP ports neither excluded nor in use,
// from one native table read.
func freeDynamicUDP4(t *testing.T, space *udpPortSpace) int {
	t.Helper()
	if space == nil || space.Probe == nil || len(space.Probe.families) == 0 || space.Probe.families[0].DynamicRange == nil {
		return -1
	}
	family := space.Probe.families[0]
	_, used, err := nativeUDPSnapshot()
	if err != nil {
		return -1
	}
	inUse := make(map[int]bool, len(used[0]))
	for _, port := range used[0] {
		inUse[int(port)] = true
	}
	free := 0
	for port := family.DynamicRange.Start; port <= family.DynamicRange.End; port++ {
		excluded := false
		for _, r := range family.ExcludedRanges {
			excluded = excluded || (port >= r.Start && port <= r.End)
		}
		if !excluded && !inUse[port] {
			free++
		}
	}
	return free
}

func nativeUDPRecoveryCycles(t *testing.T, cycles int, apps *[]*net.UDPConn, engines *[]*udpSocket, peer *net.UDPConn,
	config net.ListenConfig, source string, space *udpPortSpace, pool *udpReadiness) {
	t.Helper()
	destination := peer.LocalAddr().(*net.UDPAddr)
	var results []udpRecoveryCycle
	openPair := func(cycle *udpRecoveryCycle, phase string) {
		attempt := func(half string) (func(), error) {
			if half == "app connect" {
				app, err := net.DialUDP("udp4", nil, destination)
				if err != nil {
					return nil, err
				}
				return func() { *apps = append(*apps, app) }, nil
			}
			packet, err := config.ListenPacket(context.Background(), "udp4", net.JoinHostPort(source, "0"))
			if err != nil {
				return nil, err
			}
			conn := packet.(*net.UDPConn)
			raw, err := conn.SyscallConn()
			if err != nil {
				conn.Close()
				t.Fatal(err)
			}
			return func() {
				*engines = append(*engines, &udpSocket{conn: conn, raw: raw, pool: pool, local: conn.LocalAddr().(*net.UDPAddr).AddrPort(), mtu: 65535})
			}, nil
		}
		for _, half := range []string{"app connect", "engine bind"} {
			keep, err := attempt(half)
			if err == nil {
				keep()
				continue
			}
			refusal := udpRecoveryRefusal{Phase: phase, Half: half, Free: freeDynamicUDP4(t, space)}
			refusal.Code, refusal.Errno = udpFailureCode(err)
			time.Sleep(200 * time.Millisecond)
			if keep, err := attempt(half); err == nil {
				keep()
				refusal.RetryOK = true
			} else {
				refusal.RetryCode, refusal.RetryErrno = udpFailureCode(err)
			}
			cycle.Refusals = append(cycle.Refusals, refusal)
			if phase == "reopen" {
				cycle.ReopenRefused++
			} else {
				cycle.RestoreRefused++
			}
			if !refusal.RetryOK {
				return // like the engine run: a refused app gets no engine half
			}
		}
	}
	for range cycles {
		count := min(512, len(*apps), len(*engines))
		for i := 0; i < count; i++ {
			(*apps)[len(*apps)-1-i].Close()
			(*engines)[len(*engines)-1-i].Close()
		}
		*apps, *engines = (*apps)[:len(*apps)-count], (*engines)[:len(*engines)-count]
		time.Sleep(time.Second) // the engine run waits for its one-second reconciliation
		cycle := udpRecoveryCycle{Released: count, FreeBefore: freeDynamicUDP4(t, space)}
		for range 256 {
			cycle.Reopen++
			openPair(&cycle, "reopen")
		}
		for range 256 {
			cycle.Restore++
			openPair(&cycle, "restore")
		}
		results = append(results, cycle)
	}
	attempts, refused := 0, 0
	for _, cycle := range results {
		attempts += cycle.Reopen
		refused += cycle.ReopenRefused
	}
	evidence, _ := json.Marshal(map[string]any{"cycles": results, "reopenAttempts": attempts, "reopenRefused": refused,
		"source": source, "appBind": "wildcard port zero, connected", "engineBind": "specific source port zero, IP_UNICAST_IF"})
	t.Logf("WINDOWS NATIVE UDP RECOVERY CYCLES %s", evidence)
}
