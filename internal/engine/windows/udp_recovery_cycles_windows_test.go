//go:build windows

package winengine

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
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
	Phase   string `json:"phase"` // reopen or restore
	Half    string `json:"half"`  // app connect or engine bind
	Code    string `json:"code"`
	Errno   uint32 `json:"errno,omitempty"`
	Error   string `json:"error"`
	Free    int    `json:"freeAtRefusal"`
	RetryOK bool   `json:"retryAfter200msOK"`
	// Up to four fresh automatic attempts right after the refusal.
	ImmediateAttempts int      `json:"immediateAttempts"`
	ImmediateOK       bool     `json:"immediateOK"`
	ImmediateMicros   int64    `json:"immediateMicros"`
	ImmediateCodes    []string `json:"immediateErrors,omitempty"`
	RetryCode         string   `json:"retryCode,omitempty"`
	RetryErrno        uint32   `json:"retryErrno,omitempty"`
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

// holdNativeTCPLoad fills the TCP ephemeral pool the way the native TCP
// baseline does (production bind options, loopback listeners, 32 dials at a
// time) until Windows refuses, and holds every connection: the TCP side of
// the engine run's mixed corner, with no engine. It returns the held count
// and a release that aborts them, so no TIME_WAIT outlives the control.
func holdNativeTCPLoad(t *testing.T) (int, func()) {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var index uint32
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			index = uint32(iface.Index)
			break
		}
	}
	var mu sync.Mutex
	var held []*net.TCPConn
	var listeners []*net.TCPListener
	var acceptors sync.WaitGroup
	release := func() {
		for _, listener := range listeners {
			listener.Close()
		}
		acceptors.Wait()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range held {
			conn.SetLinger(0)
			conn.Close()
		}
		held = nil
	}
	for range 8 {
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)})
		if err != nil {
			release()
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		acceptors.Go(func() {
			for {
				peer, err := listener.AcceptTCP()
				if err != nil {
					return
				}
				mu.Lock()
				held = append(held, peer)
				mu.Unlock()
			}
		})
	}
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, Control: bindSocket(Adapter{Index4: index}, false), Timeout: 5 * time.Second}
	clients := 0
	for refused := false; !refused && clients < 65536; {
		var workers sync.WaitGroup
		var batchMu sync.Mutex
		for n := range 32 {
			remote := listeners[n%len(listeners)].Addr().String()
			workers.Go(func() {
				conn, err := dialer.DialContext(context.Background(), "tcp4", remote)
				batchMu.Lock()
				defer batchMu.Unlock()
				if err != nil {
					refused = true
					return
				}
				clients++
				mu.Lock()
				held = append(held, conn.(*net.TCPConn))
				mu.Unlock()
			})
		}
		workers.Wait()
	}
	return clients, release
}

// With halves.ready, each engine half is the engine's own native socket put
// through its readiness registration, as production sessions are; otherwise
// it is a plain Go socket with the same bind options.
func nativeUDPRecoveryCycles(t *testing.T, cycles int, halves udpEngineHalves, apps *[]*net.UDPConn, engines *[]io.Closer, peer *net.UDPConn,
	source string, space *udpPortSpace) {
	nativeUDPRecoveryCyclesWith(t, cycles, halves, 0, apps, engines, peer, source, space)
}

func nativeUDPRecoveryCyclesWith(t *testing.T, cycles int, halves udpEngineHalves, tcpLoad int, apps *[]*net.UDPConn, engines *[]io.Closer, peer *net.UDPConn,
	source string, space *udpPortSpace) {
	t.Helper()
	ready := halves.ready
	destination := peer.LocalAddr().(*net.UDPAddr)
	var results []udpRecoveryCycle
	openPair := func(cycle *udpRecoveryCycle, phase string) {
		attempt := func(half string) (func(), error) {
			if half == "app connect" {
				dial := func(peer *net.UDPAddr) (*net.UDPConn, error) { return net.DialUDP("udp4", nil, peer) }
				if halves.app != nil {
					dial = halves.app
				}
				app, err := dial(destination)
				if err != nil {
					return nil, err
				}
				return func() { *apps = append(*apps, app) }, nil
			}
			engine, err := halves.open()
			if err != nil {
				return nil, err
			}
			return func() { *engines = append(*engines, engine) }, nil
		}
		for _, half := range []string{"app connect", "engine bind"} {
			keep, err := attempt(half)
			if err == nil {
				keep()
				continue
			}
			refusal := udpRecoveryRefusal{Phase: phase, Half: half, Error: err.Error(), Free: freeDynamicUDP4(t, space)}
			refusal.Code, refusal.Errno = udpFailureCode(err)
			// Measured, never counted as the first attempt: up to four fresh
			// automatic attempts straight away (each a new socket, port 0),
			// then the later 200 ms attempt only if all of them failed.
			started := time.Now()
			for n := 1; n <= 4 && !refusal.RetryOK; n++ {
				refusal.ImmediateAttempts = n
				if keep, err := attempt(half); err == nil {
					keep()
					refusal.RetryOK, refusal.ImmediateOK = true, true
				} else {
					refusal.ImmediateCodes = append(refusal.ImmediateCodes, err.Error())
				}
			}
			refusal.ImmediateMicros = time.Since(started).Microseconds()
			if !refusal.RetryOK {
				time.Sleep(200 * time.Millisecond)
				if keep, err := attempt(half); err == nil {
					keep()
					refusal.RetryOK = true
				} else {
					refusal.RetryCode, refusal.RetryErrno = udpFailureCode(err)
				}
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
	evidence, _ := json.Marshal(map[string]any{"readyUDP": ready, "tcpLoad": tcpLoad, "cycles": results, "reopenAttempts": attempts, "reopenRefused": refused,
		"source": source, "appBind": "wildcard port zero, connected", "engineBind": "specific source port zero, IP_UNICAST_IF",
		"engineSocket": halves.kind()})
	t.Logf("WINDOWS NATIVE UDP RECOVERY CYCLES %s", evidence)
}
