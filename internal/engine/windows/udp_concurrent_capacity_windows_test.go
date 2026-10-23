//go:build windows

package winengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/winclock"
	"golang.org/x/sys/windows"
)

// The real engine harness admits app flows in groups of 32. This oracle opens
// native pairs the same way, beside the unchanged sequential baseline in
// TestNativeUDPPairedCapacity. It is diagnostics only: no floor, gate or
// engine fix rests on it.
const udpPairConcurrency = 32

var errPairMismatch = errors.New("UDP pair payload or source mismatch")

type udpPairFailure struct {
	Pair       int     `json:"pair"`
	Call       string  `json:"call"`
	Code       string  `json:"code"`
	Errno      uint32  `json:"errno,omitempty"`
	Error      string  `json:"error"`
	At         string  `json:"at"`
	ElapsedMS  float64 `json:"elapsedMS"`
	Handle     uintptr `json:"nativeHandle,omitempty"`
	CloseError string  `json:"closeError,omitempty"`
}

// A pair is held only when both halves echoed exactly; a failed pair owns
// nothing.
type udpConcurrentPair struct {
	app     *net.UDPConn
	engine  io.Closer // a plain Go socket, or the engine's native socket
	local   netip.AddrPort
	appPort uint16
	handle  uintptr
	options map[string]int
	failure *udpPairFailure
}

func udpFailureCode(err error) (string, uint32) {
	if errors.Is(err, errPairMismatch) {
		return "MISMATCH", 0
	}
	if errors.Is(err, platform.ErrDatagramDropped) {
		return "SEND_DROPPED", 0 // WSAENOBUFS from a send, mapped by udpSocket.
	}
	var errno windows.Errno
	if errors.As(err, &errno) {
		switch errno {
		case windows.WSAENOBUFS:
			return "ENOBUFS", uint32(errno)
		case windows.WSAEADDRINUSE:
			return "EADDRINUSE", uint32(errno)
		}
		return "ERRNO", uint32(errno)
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "TIMEOUT", 0
	}
	return "OTHER", 0
}

// fail records the failing call and closes both halves. udpSocket.Close
// detaches a readiness watch before it closes the native handle.
func (p *udpConcurrentPair) fail(pair int, call string, err error, started time.Duration) {
	code, errno := udpFailureCode(err)
	p.failure = &udpPairFailure{Pair: pair, Call: call, Code: code, Errno: errno, Error: err.Error(),
		At: time.Now().UTC().Format(time.RFC3339Nano), Handle: p.handle,
		ElapsedMS: float64(winclock.Since(started)) / float64(time.Millisecond)}
	var closeErr error
	if p.app != nil {
		closeErr = p.app.Close()
	}
	if p.engine != nil {
		closeErr = errors.Join(closeErr, p.engine.Close())
	}
	if closeErr != nil {
		p.failure.CloseError = closeErr.Error()
	}
	p.app, p.engine = nil, nil
}

// udpPairPeer echoes every datagram exactly and records each payload's
// observed source before replying, so a received reply proves the record.
type udpPairPeer struct {
	conn                                      *net.UDPConn
	mu                                        sync.Mutex
	seen                                      map[string]netip.AddrPort
	echoed, malformed, duplicates, readErrors int
	writeErrors                               int
	lastError                                 string
	done                                      chan struct{}
}

func (p *udpPairPeer) run() {
	defer close(p.done)
	var b [128]byte
	for {
		n, from, err := p.conn.ReadFromUDPAddrPort(b[:])
		if errors.Is(err, net.ErrClosed) {
			return
		}
		p.mu.Lock()
		if err != nil {
			p.readErrors++
			p.lastError = err.Error()
			stop := p.readErrors > 1000
			p.mu.Unlock()
			if stop {
				return
			}
			continue
		}
		payload := string(b[:n])
		if !strings.HasPrefix(payload, "NSPAIR ") {
			p.malformed++
		} else {
			if _, ok := p.seen[payload]; ok {
				p.duplicates++
			}
			p.seen[payload] = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		}
		p.mu.Unlock()
		_, err = p.conn.WriteToUDPAddrPort(b[:n], from)
		p.mu.Lock()
		if err != nil {
			p.writeErrors++
			p.lastError = err.Error()
		} else {
			p.echoed++
		}
		p.mu.Unlock()
	}
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func udpPairToken(variant string, half byte, pair int) string {
	return fmt.Sprintf("NSPAIR %s %c %06d", variant, half, pair)
}

// udpOwnRows counts this process's rows in the native UDP owner table, an
// accounting independent of the test's own held list.
func udpOwnRows(native map[string]any) (int, error) {
	raw, err := json.Marshal(native["groups"])
	if err != nil {
		return 0, err
	}
	var groups []struct {
		PID   int      `json:"pid"`
		Ports []uint16 `json:"ports"`
	}
	if err := json.Unmarshal(raw, &groups); err != nil {
		return 0, err
	}
	rows := 0
	for _, group := range groups {
		if group.PID == os.Getpid() {
			rows += len(group.Ports)
		}
	}
	return rows, nil
}

func TestNativeUDPConcurrentPairedCapacity(t *testing.T) {
	hosted(t)
	if os.Getenv("NETSWITCH_PORT_GATE") != "1" {
		t.Skip("native UDP pair isolation belongs to the hosted capacity fixture")
	}
	requireProcessDiagnostics(t)
	index, source, peerSource := udpPairBinding(t)
	for _, native := range []bool{false, true} {
		variant := map[bool]string{false: "Go", true: "ReadyUDP"}[native]
		t.Run(variant, func(t *testing.T) {
			before := systemResources()
			conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: peerSource})
			if err != nil {
				t.Fatal(err)
			}
			peer := &udpPairPeer{conn: conn, seen: map[string]netip.AddrPort{}, done: make(chan struct{})}
			go peer.run()
			stopPeer := sync.OnceFunc(func() {
				peer.conn.Close()
				<-peer.done
			})
			defer stopPeer()
			pool, err := newUDPReadiness(nil)
			if err != nil {
				t.Fatal(err)
			}
			var held []udpConcurrentPair
			var releaseErr error
			release := sync.OnceFunc(func() {
				for _, p := range held {
					releaseErr = errors.Join(releaseErr, p.app.Close(), p.engine.Close())
				}
				releaseErr = errors.Join(releaseErr, pool.close())
			})
			defer release()
			halves := newUDPEngineHalves(native, index, source, pool)
			destination := conn.LocalAddr().(*net.UDPAddr).AddrPort()
			destination = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
			unmapped := func(a netip.AddrPort) netip.AddrPort { return netip.AddrPortFrom(a.Addr().Unmap(), a.Port()) }
			started := winclock.Now()

			// open performs one pair exactly like the sequential baseline. It never
			// retries: any failure closes both halves and is reported.
			open := func(n int) (p udpConcurrentPair) {
				app, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(destination))
				if err != nil {
					p.fail(n, "app DialUDP", err, started)
					return
				}
				p.app, p.appPort = app, uint16(app.LocalAddr().(*net.UDPAddr).Port)
				wake := make(chan struct{}, 1)
				var watch *udpWatch
				var engineConn *net.UDPConn
				var engineSocket *udpSocket
				if native {
					// The engine's own constructor, then Watch. The callback only
					// enqueues; it never blocks the shared worker.
					engineSocket, watch, err = halves.openReady(func() {
						select {
						case wake <- struct{}{}:
						default:
						}
					})
					if err != nil {
						p.fail(n, "engine bind", err, started)
						return
					}
					p.engine, p.local = engineSocket, engineSocket.LocalAddr()
					p.handle = uintptr(engineSocket.handle.Handle("UDP concurrent capacity evidence"))
				} else {
					engineConn, err = halves.openGo()
					if err != nil {
						p.fail(n, "engine bind", err, started)
						return
					}
					p.engine, p.local = engineConn, engineConn.LocalAddr().(*net.UDPAddr).AddrPort()
				}
				if n == 0 {
					p.options = map[string]int{}
					read := func(h windows.Handle) error {
						for name, option := range map[string]int{"SO_REUSEADDR": windows.SO_REUSEADDR, "SO_EXCLUSIVEADDRUSE": ^windows.SO_REUSEADDR} {
							value, err := windows.GetsockoptInt(h, windows.SOL_SOCKET, option)
							if err != nil {
								return err
							}
							p.options[name] = value
						}
						return nil
					}
					var optionErr error
					if native {
						optionErr = read(engineSocket.handle.Handle("UDP concurrent capacity options"))
					} else if raw, err := engineConn.SyscallConn(); err != nil {
						optionErr = err
					} else {
						var readErr error
						controlErr := raw.Control(func(fd uintptr) { readErr = read(windows.Handle(fd)) })
						optionErr = errors.Join(controlErr, readErr)
					}
					if optionErr != nil {
						p.fail(n, "engine socket options", optionErr, started)
						return
					}
				}
				var b [128]byte
				request := []byte(udpPairToken(variant, 'A', n))
				app.SetDeadline(time.Now().Add(2 * time.Second))
				if _, err := app.Write(request); err != nil {
					p.fail(n, "app write", err, started)
					return
				}
				got, from, err := app.ReadFromUDPAddrPort(b[:])
				if err == nil && (!bytes.Equal(b[:got], request) || unmapped(from) != destination) {
					err = fmt.Errorf("%w: n=%d source=%s", errPairMismatch, got, from)
				}
				if err != nil {
					p.fail(n, "app receive", err, started)
					return
				}
				request = []byte(udpPairToken(variant, 'E', n))
				if native {
					if err := watch.Arm(true, false); err != nil {
						p.fail(n, "engine Arm", err, started)
						return
					}
					if _, err := engineSocket.TryWriteTo(request, destination, false); err != nil {
						p.fail(n, "engine write", err, started)
						return
					}
					timer := time.NewTimer(2 * time.Second)
					select {
					case <-wake:
						timer.Stop()
					case <-timer.C:
						p.fail(n, "engine readiness wake", os.ErrDeadlineExceeded, started)
						return
					}
					got, from, err = engineSocket.TryReadFrom(b[:])
				} else {
					if _, err := engineConn.WriteToUDPAddrPort(request, destination); err != nil {
						p.fail(n, "engine write", err, started)
						return
					}
					engineConn.SetReadDeadline(time.Now().Add(2 * time.Second))
					got, from, err = engineConn.ReadFromUDPAddrPort(b[:])
				}
				if err == nil && (!bytes.Equal(b[:got], request) || unmapped(from) != destination) {
					err = fmt.Errorf("%w: n=%d source=%s", errPairMismatch, got, from)
				}
				if err != nil {
					p.fail(n, "engine receive", err, started)
				}
				return
			}

			var failures []udpPairFailure
			var options map[string]int
			attempted, batches, verified := 0, 0, 0
			// Stop after the first batch with any failure; that batch's
			// successful pairs are still held.
			for attempted < 12000 && len(failures) == 0 {
				results := make([]udpConcurrentPair, udpPairConcurrency)
				var workers sync.WaitGroup
				for i := range results {
					workers.Go(func() { results[i] = open(attempted + i) })
				}
				workers.Wait()
				// Each held pair must match the peer's own record of both
				// requests and their sources.
				var mismatched []int
				peer.mu.Lock()
				for i := range results {
					p, n := &results[i], attempted+i
					if p.failure != nil {
						continue
					}
					a, appSeen := peer.seen[udpPairToken(variant, 'A', n)]
					e, engineSeen := peer.seen[udpPairToken(variant, 'E', n)]
					if appSeen && engineSeen && a.Port() == p.appPort && e == unmapped(p.local) {
						verified += 2
					} else {
						mismatched = append(mismatched, i)
					}
				}
				peer.mu.Unlock()
				for _, i := range mismatched {
					results[i].fail(attempted+i, "peer source record", errPairMismatch, started)
				}
				for _, p := range results {
					if p.options != nil {
						options = p.options
					}
					if p.failure != nil {
						failures = append(failures, *p.failure)
					} else {
						held = append(held, p)
					}
				}
				attempted += len(results)
				batches++
			}

			// Diagnose while every admitted socket is still held.
			heldResources := systemResources()
			space := diagnoseUDPPortSpace(context.Background())
			memory, memoryErr := processMemory()
			ownRows, ownRowsErr := udpOwnRows(space.Native)
			ports := map[uint16]int{}
			for _, p := range held {
				ports[p.appPort]++
				ports[p.local.Port()]++
			}
			collisions := 0
			for _, count := range ports {
				if count > 1 {
					collisions++
				}
			}
			heldPairs := len(held)
			stopPeer()
			release()
			afterRelease := systemResources()

			var first *udpPairFailure
			for i := range failures {
				if first == nil || failures[i].ElapsedMS < first.ElapsedMS {
					first = &failures[i]
				}
			}
			limitReached := first != nil && (first.Code == "ENOBUFS" || first.Code == "EADDRINUSE")
			evidence := map[string]any{"mode": "concurrent", "concurrency": udpPairConcurrency,
				"variant": variant, "readyUDP": native,
				"baseline":  "sequential TestNativeUDPPairedCapacity is separate and unchanged",
				"verdict":   "diagnostic only; no floor, gate or engine-fix claim",
				"heldPairs": heldPairs, "attemptedPairs": attempted, "batches": batches,
				"uniquePorts": len(ports), "portCollisions": collisions,
				"verifiedPayloads": verified, "peerEchoed": peer.echoed, "peerDuplicates": peer.duplicates,
				"peerMalformed": peer.malformed, "peerReadErrors": peer.readErrors, "peerWriteErrors": peer.writeErrors,
				"peerLastError": peer.lastError,
				"firstFailure":  first, "failingBatch": failures, "limitReached": limitReached,
				"family": "ipv4", "source": source, "interfaceIndex": index,
				"appBind": "wildcard port zero, connected", "engineBind": "specific source port zero, IP_UNICAST_IF",
				"engineOptions": options, "portSpace": space.Probe,
				"nativeUDPRows": space.Native["rowsByFamily"], "nativeUDPUniquePorts": space.Native["uniquePorts"],
				"nativeUDPError": space.Native["error"], "nativeOwnRows": ownRows, "nativeOwnRowsError": errorText(ownRowsErr),
				"nativeOwnRowsExpected": 2*heldPairs + 1,
				"resourcesBefore":       before, "resourcesHeld": heldResources, "resourcesAfterRelease": afterRelease,
				"processMemory": memory, "memoryError": errorText(memoryErr), "releaseError": errorText(releaseErr)}
			line, err := json.Marshal(evidence)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("WINDOWS NATIVE UDP CONCURRENT PAIRED CAPACITY %s", line)
			if !limitReached {
				t.Errorf("concurrent native pair limit was not established: first failure %+v", first)
			}
			for _, failure := range failures {
				if (failure.Call != "app DialUDP" && failure.Call != "engine bind") ||
					(failure.Code != "ENOBUFS" && failure.Code != "EADDRINUSE") || failure.CloseError != "" {
					t.Errorf("unrelated failure in the exhausted batch: %+v", failure)
				}
			}
			if verified != 2*heldPairs || peer.echoed != verified || peer.duplicates != 0 || peer.malformed != 0 || peer.readErrors != 0 || peer.writeErrors != 0 {
				t.Errorf("held pairs disagree with peer records: held=%d verified=%d duplicates=%d malformed=%d",
					heldPairs, verified, peer.duplicates, peer.malformed)
			}
			if ownRowsErr != nil || space.Native["error"] != nil || ownRows != 2*heldPairs+1 || len(ports) != 2*heldPairs || collisions != 0 {
				t.Errorf("held pairs disagree with native table: own rows=%d expected=%d unique=%d collisions=%d errors=%v/%v",
					ownRows, 2*heldPairs+1, len(ports), collisions, ownRowsErr, space.Native["error"])
			}
			if releaseErr != nil {
				t.Error(releaseErr)
			}
		})
	}
}
