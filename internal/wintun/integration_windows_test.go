//go:build windows

package wintun

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/platform/winapi"
	"golang.org/x/sys/windows"
)

func requireRunner(t *testing.T) {
	t.Helper()
	if os.Getenv("NETSWITCH_WINTUN_CI") != "1" {
		t.Skip("real Wintun tests run only in the dedicated hosted CI job")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Fatal("refusing Wintun integration test outside a GitHub-hosted runner")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func report(t *testing.T, value any) {
	t.Helper()
	if integrityHooksEnabled && os.Getenv("NETSWITCH_WINTUN_INTEGRITY_TRACE") == "1" {
		integrityReportContext(t, value)
	}
	b, err := json.Marshal(value)
	must(t, err)
	t.Logf("WINTUN_RESULT %s", b)
}

var performanceCounter = windows.NewLazySystemDLL("kernel32.dll").NewProc("QueryPerformanceCounter")
var performanceFrequency = sync.OnceValue(func() int64 {
	var n int64
	ok, _, err := windows.NewLazySystemDLL("kernel32.dll").NewProc("QueryPerformanceFrequency").Call(uintptr(unsafe.Pointer(&n)))
	if ok == 0 || n <= 0 {
		panic(fmt.Sprintf("performance clock: %v", err))
	}
	return n
})

func ticks() int64 {
	var n int64
	ok, _, err := performanceCounter.Call(uintptr(unsafe.Pointer(&n)))
	if ok == 0 {
		panic(fmt.Sprintf("performance counter: %v", err))
	}
	return n
}

func elapsed(start int64) time.Duration {
	return time.Duration(float64(ticks()-start) * 1e9 / float64(performanceFrequency()))
}

func command(t *testing.T, program string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, program, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", program, args, err, b)
	}
	return strings.TrimSpace(string(b))
}

func runUDPClient(t *testing.T, streams int) (float64, error) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, exe, "-test.run=^TestWintunUDPClient$", "-test.v")
	child.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	child.Env = append(os.Environ(), fmt.Sprintf("NETSWITCH_WINTUN_UDP_STREAMS=%d", streams))
	output, err := child.CombinedOutput()
	if err != nil {
		if bytes.Contains(output, []byte(errPayloadIntegrity.Error())) {
			err = errors.Join(errPayloadIntegrity, err)
		}
		return 0, fmt.Errorf("UDP client: %w\n%s", err, output)
	}
	var rate float64
	found := false
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "UDP_CLIENT_RESULT ") {
			if _, err := fmt.Sscanf(line, "UDP_CLIENT_RESULT %f", &rate); err != nil {
				return 0, err
			}
			found = true
		}
		if i := strings.Index(line, "WINTUN_RESULT "); i >= 0 {
			var value map[string]any
			if err := json.Unmarshal([]byte(strings.TrimSpace(line[i+14:])), &value); err != nil {
				return 0, err
			}
			value["client_process"] = true
			report(t, value)
		}
	}
	if !found {
		return 0, fmt.Errorf("UDP client exited without running its traffic test: %s", output)
	}
	return rate, nil
}

type batchIO interface {
	ReadBatch(context.Context, [][]byte, []int) (int, error)
	WriteBatch([][]byte) (int, error)
	Close() error
}

type fixture struct {
	mode           string
	wordBoundaries wordBoundaryCapture
	// Only the hosted capture overhead proof sets this, for its SHA-only baseline.
	skipPayloadCapture bool
	captureVariant     string
	capturePair        int
	integrity          *integrityDiagnostic
	a                  *Adapter
	io                 batchIO
	stopEcho           func()
	faults             atomic.Uint64
	faultMu            sync.Mutex
	lastFault          error
}

func (f *fixture) recordFault(err error) {
	f.faults.Add(1)
	f.faultMu.Lock()
	f.lastFault = err
	f.faultMu.Unlock()
}

func (f *fixture) fault() error {
	f.faultMu.Lock()
	defer f.faultMu.Unlock()
	return f.lastFault
}

func newAdapter(t *testing.T, capacity uint32) *Adapter {
	t.Helper()
	requireRunner(t)
	guid, err := windows.GenerateGUID()
	must(t, err)
	a, err := Create(Config{Name: "NsRingCI", GUID: guid.String(), Capacity: capacity})
	must(t, err)
	integrityAdapterState(t, a, "created", nil)
	t.Cleanup(func() {
		err := a.Close()
		integrityAdapterState(t, a, "closed", err)
		must(t, err)
	})
	command(t, "netsh.exe", "interface", "ipv4", "set", "interface", "NsRingCI", "dadtransmits=0", "store=active")
	command(t, "netsh.exe", "interface", "ipv4", "set", "address", "name=NsRingCI", "source=static", "address=198.19.240.1", "mask=255.255.255.252", "gateway=none", "store=active")
	command(t, "netsh.exe", "interface", "ipv4", "set", "subinterface", "NsRingCI", "mtu=9000", "store=active")
	return a
}

func startIO(t *testing.T, a *Adapter, mode string) batchIO {
	t.Helper()
	if mode == "dll" {
		return startDLL(t, a)
	}
	start := a.StartSession // "ours": the production registrar path
	if mode == "inprocess" {
		start = a.startInProcessSession // test-only former baseline
	} else if mode != "ours" {
		t.Fatalf("unknown session mode %q", mode)
	}
	s, err := start()
	must(t, err)
	return s
}

func newFixture(t *testing.T, mode string, capacity uint32) *fixture {
	t.Helper()
	return fixtureOnAdapter(t, mode, newAdapter(t, capacity))
}

func fixtureOnAdapter(t *testing.T, mode string, adapter *Adapter) *fixture {
	t.Helper()
	f := &fixture{a: adapter, mode: mode}
	f.io = startIO(t, f.a, mode)
	integrityFixtureState(t, f, mode, "started", nil)
	f.startEcho(t)
	t.Cleanup(func() {
		f.stopEcho()
		integrityFixtureState(t, f, mode, "pumps_joined", nil)
		err := f.io.Close()
		integrityFixtureState(t, f, mode, "closed", err)
		must(t, err)
	})
	// Let Windows finish link/address activation. These are warm-up packets,
	// explicitly outside the measured sample.
	c := udpSocket(t)
	defer c.Close()
	for i := 0; i < 30; i++ {
		c.SetDeadline(time.Now().Add(100 * time.Millisecond))
		_, err := c.Write([]byte("warmup"))
		if err == nil {
			_, err = c.Read(make([]byte, 64))
		}
		if err == nil {
			return f
		}
	}
	t.Fatal("adapter did not become ready")
	return nil
}

func udpSocket(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP("198.19.240.1")}, &net.UDPAddr{IP: net.ParseIP("198.19.240.2"), Port: 9001})
	must(t, err)
	c.SetReadBuffer(4 << 20)
	return c
}

func echoUDP(p []byte) bool {
	if len(p) < 28 || p[0] != 0x45 || p[9] != 17 || !bytes.Equal(p[16:20], []byte{198, 19, 240, 2}) || binary.BigEndian.Uint16(p[22:24]) != 9001 || !validIP(p) {
		return false
	}
	for i := 0; i < 4; i++ {
		p[12+i], p[16+i] = p[16+i], p[12+i]
	}
	p[20], p[22] = p[22], p[20]
	p[21], p[23] = p[23], p[21]
	// Swapping endpoints preserves both one's-complement checksums.
	return true
}

func (f *fixture) startEcho(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffers := make([][]byte, 64)
		sizes := make([]int, 64)
		for i := range buffers {
			buffers[i] = make([]byte, MaxPacketSize)
		}
		out := make([][]byte, 0, len(buffers))
		for {
			n, err := f.io.ReadBatch(ctx, buffers, sizes)
			if err != nil {
				if ctx.Err() == nil {
					f.recordFault(err)
					t.Logf("echo read: %v", err)
				}
				return
			}
			out = out[:0]
			for i := 0; i < n; i++ {
				p := buffers[i][:sizes[i]]
				if echoUDP(p) {
					out = append(out, p)
				}
			}
			if _, err = f.io.WriteBatch(out); err != nil && ctx.Err() == nil {
				f.recordFault(err)
				t.Logf("echo write: %v", err)
			}
		}
	}()
	f.stopEcho = func() { cancel(); <-done }
}

// DLL sessions exist only in tests as the signed-release comparison. Native
// copies avoid manufacturing Go pointers from the DLL's integer return values.
type dllSession struct {
	integrity                             *integrityDiagnostic
	mu                                    sync.RWMutex
	readMu, writeMu                       sync.Mutex
	h                                     uintptr
	event, stop, cancelEvent              windows.Handle
	receive, release, allocate, send, end uintptr
	closed                                atomic.Bool
	readPackets, readWaits, readWakes     atomic.Uint64
	writtenPackets, writeBatches          atomic.Uint64
}

var nativeCopy = windows.NewLazySystemDLL("ntdll.dll").NewProc("RtlMoveMemory")

func startDLL(t *testing.T, a *Adapter) *dllSession {
	t.Helper()
	s := &dllSession{}
	for name, dst := range map[string]*uintptr{"WintunReceivePacket": &s.receive, "WintunReleaseReceivePacket": &s.release, "WintunAllocateSendPacket": &s.allocate, "WintunSendPacket": &s.send, "WintunEndSession": &s.end} {
		p, err := windows.GetProcAddress(a.dll.module, name)
		must(t, err)
		*dst = p
	}
	start, err := windows.GetProcAddress(a.dll.module, "WintunStartSession")
	must(t, err)
	h, _, e := syscall.SyscallN(start, a.handle, uintptr(a.config.Capacity))
	if h == 0 {
		t.Fatal(e)
	}
	s.h = h
	get, err := windows.GetProcAddress(a.dll.module, "WintunGetReadWaitEvent")
	must(t, err)
	event, _, _ := syscall.SyscallN(get, h)
	s.event = windows.Handle(event)
	s.stop, err = windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		syscall.SyscallN(s.end, s.h)
		t.Fatal(err)
	}
	s.cancelEvent, err = windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		windows.CloseHandle(s.stop)
		syscall.SyscallN(s.end, s.h)
		t.Fatal(err)
	}
	return s
}

func (s *dllSession) ReadBatch(ctx context.Context, buffers [][]byte, sizes []int) (n int, err error) {
	defer func() { s.readPackets.Add(uint64(n)) }()
	s.readMu.Lock()
	defer s.readMu.Unlock()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	var cancelEvent windows.Handle
	for {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		if s.closed.Load() {
			return 0, net.ErrClosed
		}
		for i := range buffers {
			var size uint32
			p, _, e := syscall.SyscallN(s.receive, s.h, uintptr(unsafe.Pointer(&size)))
			if p == 0 {
				if e == windows.ERROR_INVALID_DATA {
					return i, fmt.Errorf("%w: DLL receive ring: %w", errPayloadIntegrity, e)
				}
				if e != windows.ERROR_NO_MORE_ITEMS {
					return i, e
				}
				if i != 0 {
					return i, nil
				}
				break
			}
			if int(size) > len(buffers[i]) {
				syscall.SyscallN(s.release, s.h, p)
				return i, io.ErrShortBuffer
			}
			if size != 0 {
				nativeCopy.Call(uintptr(unsafe.Pointer(&buffers[i][0])), p, uintptr(size))
			}
			if wordBoundaryHooksEnabled {
				observeWordDLL("ring_ingress", buffers[i][:size])
			}
			if integrityHooksEnabled && s.integrity != nil && (s.integrity.selected("dll_receive") || integritySYN(buffers[i][:size])) {
				s.integrity.nativeAddress("dll_receive", p, buffers[i][:size])
			}
			syscall.SyscallN(s.release, s.h, p)
			sizes[i] = int(size)
			if i == len(buffers)-1 {
				return len(buffers), nil
			}
		}
		// Give the reference wrapper the same lazy cancellation setup as our
		// production reader, so ready-batch allocation does not bias the comparison.
		if cancelEvent == 0 && ctx.Done() != nil {
			event := s.cancelEvent
			cancelEvent = event
			done := make(chan struct{})
			stop := context.AfterFunc(ctx, func() { windows.SetEvent(event); close(done) })
			defer func() {
				if !stop() {
					<-done
					windows.ResetEvent(event)
				}
			}()
		}
		handles := []windows.Handle{s.stop, s.event}
		if cancelEvent != 0 {
			handles = append(handles, cancelEvent)
		}
		s.readWaits.Add(1)
		_, err := winapi.WaitForMultipleObjects(handles, false, windows.INFINITE)
		if err == nil {
			s.readWakes.Add(1)
		}
		if err != nil {
			return 0, err
		}
	}
}

func (s *dllSession) WriteBatch(packets [][]byte) (n int, err error) {
	defer func() {
		s.writtenPackets.Add(uint64(n))
		if n != 0 {
			s.writeBatches.Add(1)
		}
	}()
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	for _, b := range packets {
		p, _, e := syscall.SyscallN(s.allocate, s.h, uintptr(len(b)))
		if p == 0 {
			if e == windows.ERROR_BUFFER_OVERFLOW {
				continue
			}
			return n, e
		}
		nativeCopy.Call(p, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
		if wordBoundaryHooksEnabled {
			observeWordDLL("ring_publish", mappedSlice(p, len(b)))
		}
		if integrityHooksEnabled && s.integrity != nil && s.integrity.selected("dll_send") {
			s.integrity.nativeAddress("dll_send", p, b)
		}
		syscall.SyscallN(s.send, s.h, p)
		n++
	}
	return n, nil
}

func (s *dllSession) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	windows.SetEvent(s.stop)
	s.mu.Lock()
	defer s.mu.Unlock()
	syscall.SyscallN(s.end, s.h)
	return errors.Join(windows.CloseHandle(s.stop), windows.CloseHandle(s.cancelEvent))
}

type latencyResult struct {
	Arch              string  `json:"arch"`
	Mode              string  `json:"mode"`
	RoundTrips        int     `json:"round_trips"`
	Over50MS          int     `json:"over_50_ms"`
	EnvironmentPauses int     `json:"environment_pauses"`
	SessionStalls     int     `json:"session_stalls"`
	TimeoutRescues    int     `json:"timeout_rescues"`
	MaxMS             float64 `json:"max_ms"`
	P50US             float64 `json:"p50_us"`
	P95US             float64 `json:"p95_us"`
	P99US             float64 `json:"p99_us"`
}

func TestWintunPingPong(t *testing.T) {
	requireRunner(t)
	for _, mode := range []string{"dll", "ours"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, mode, 0)
			c := udpSocket(t)
			defer c.Close()
			s, _ := f.io.(*Session)
			monitor := startPauseMonitor(t, s)
			type slowTrip struct {
				sequence   int
				start, end int64
				rescued    bool
				state      *sessionObservation
			}
			var slow []slowTrip
			result := latencyResult{Arch: runtime.GOARCH, Mode: mode, RoundTrips: 200000}
			timings := make([]time.Duration, 0, result.RoundTrips)
			payload := make([]byte, 64)
			reply := make([]byte, 128)
			for i := 0; i < result.RoundTrips; i++ {
				// Vary the quiet period across the driver's 100 us spin-to-sleep
				// boundary. There is still only one application datagram in flight.
				quiet := ticks()
				for elapsed(quiet) < time.Duration((i*37)%201)*time.Microsecond {
					runtime.Gosched()
				}
				binary.LittleEndian.PutUint64(payload, uint64(i))
				must(t, c.SetDeadline(time.Now().Add(250*time.Millisecond)))
				start := ticks()
				monitor.inflight.Store(start)
				_, err := c.Write(payload)
				must(t, err)
				rescued := false
				for {
					n, err := c.Read(reply)
					if err != nil {
						var timeout net.Error
						if errors.As(err, &timeout) && timeout.Timeout() && !rescued {
							// A missed wake leaves a lone UDP packet queued forever.
							// After recording the timeout, one retry releases it. Never
							// remove this attempt from the latency distribution.
							rescued = true
							result.TimeoutRescues++
							must(t, c.SetDeadline(time.Now().Add(time.Second)))
							_, err = c.Write(payload)
							must(t, err)
							continue
						}
						must(t, err)
					}
					if n >= 8 && binary.LittleEndian.Uint64(reply[:8]) < uint64(i) {
						continue
					}
					if !bytes.Equal(payload, reply[:n]) {
						t.Fatal(fmt.Errorf("%w: ping-pong payload corruption", errPayloadIntegrity))
					}
					break
				}
				end := ticks()
				monitor.inflight.Store(0)
				d := qpcDuration(start, end)
				timings = append(timings, d)
				if d > 50*time.Millisecond {
					result.Over50MS++
					slow = append(slow, slowTrip{i, start, end, rescued, observeSession(s)})
				}
				if float64(d)/float64(time.Millisecond) > result.MaxMS {
					result.MaxMS = float64(d) / float64(time.Millisecond)
				}
			}
			// Classify after both samplers have observed the end of the run. Logging
			// or stopping the world for ReadMemStats in the hot loop creates noise.
			monitor.finish(t)
			for _, trip := range slow {
				states := make([]tripObservation, 0)
				for _, state := range monitor.states {
					if state.Start == trip.start && state.At >= trip.start && state.At <= trip.end {
						states = append(states, state)
					}
				}
				heartbeat := overlappingGaps(monitor.gaps[0], trip.start, trip.end)
				scheduler := overlappingGaps(monitor.gaps[1], trip.start, trip.end)
				classification, covered := classifyPause(trip.start, trip.end, trip.rescued, heartbeat, scheduler)
				if classification == "environment_pause" {
					result.EnvironmentPauses++
				} else {
					result.SessionStalls++
				}
				report(t, map[string]any{"test": "slow_round_trip", "arch": runtime.GOARCH, "mode": mode, "sequence": trip.sequence, "ms": qpcDuration(trip.start, trip.end).Seconds() * 1000, "start_qpc": trip.start, "end_qpc": trip.end, "qpc_frequency": performanceFrequency(), "rescued": trip.rescued, "classification": classification, "common_pause_ms": covered.Seconds() * 1000, "unexplained_ms": (qpcDuration(trip.start, trip.end) - covered).Seconds() * 1000, "heartbeat_gaps": heartbeat, "scheduler_gaps": scheduler, "heartbeat_samples_qpc": overlappingSamples(monitor.timestamps[0], trip.start, trip.end), "scheduler_samples_qpc": overlappingSamples(monitor.timestamps[1], trip.start, trip.end), "states_during_delay": states, "state_at_reply": trip.state})
			}
			report(t, map[string]any{"test": "pause_monitor", "arch": runtime.GOARCH, "mode": mode, "samples": monitor.samples, "heartbeat_gaps": len(monitor.gaps[0]), "scheduler_gaps": len(monitor.gaps[1])})
			sort.Slice(timings, func(i, j int) bool { return timings[i] < timings[j] })
			result.P50US = float64(timings[len(timings)/2]) / 1000
			result.P95US = float64(timings[len(timings)*95/100]) / 1000
			result.P99US = float64(timings[len(timings)*99/100]) / 1000
			report(t, result)
			if mode == "ours" && result.SessionStalls != 0 {
				t.Errorf("own session had %d unexplained round trips over 50 ms", result.SessionStalls)
			}
			if mode == "ours" && result.TimeoutRescues != 0 {
				t.Errorf("own session needed %d missed-wake rescues", result.TimeoutRescues)
			}
			if mode == "dll" && result.Over50MS == 0 {
				t.Log("DLL missed-wake race NOT reproduced in this sample")
			}
			if f.faults.Load() != 0 {
				t.Fatal("echo failed")
			}
		})
	}
}

func TestWintunParallelUDP(t *testing.T) {
	requireRunner(t)
	a := newAdapter(t, MinCapacity)
	s, err := a.StartSession()
	must(t, err)
	defer s.Close()
	var received, invalid, readErrors atomic.Uint64
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		bufs := make([][]byte, 64)
		sizes := make([]int, 64)
		for i := range bufs {
			bufs[i] = make([]byte, MaxPacketSize)
		}
		for {
			n, err := s.ReadBatch(ctx, bufs, sizes)
			if err != nil {
				if ctx.Err() == nil {
					readErrors.Add(1)
					t.Log(err)
				}
				return
			}
			for i := 0; i < n; i++ {
				p := bufs[i][:sizes[i]]
				if len(p) < 28 || p[0] != 0x45 || p[9] != 17 || !bytes.Equal(p[16:20], []byte{198, 19, 240, 2}) || binary.BigEndian.Uint16(p[22:24]) != 9001 {
					continue
				}
				body := p[28:]
				if len(body) != 1200 || !validIP(p) {
					invalid.Add(1)
					continue
				}
				id := binary.LittleEndian.Uint32(body)
				seq := binary.LittleEndian.Uint32(body[4:])
				if id >= 32 || seq >= 100000 {
					invalid.Add(1)
					continue
				}
				for j := 8; j < len(body); j++ {
					if body[j] != byte(id+seq+uint32(j)) {
						invalid.Add(1)
						break
					}
				}
				received.Add(1)
			}
		}
	}()
	var wg sync.WaitGroup
	var sent, sendErrors atomic.Uint64
	start := time.Now()
	for id := 0; id < 32; id++ {
		c := udpSocket(t)
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer c.Close()
			body := make([]byte, 1200)
			for seq := 0; seq < 100000; seq++ {
				binary.LittleEndian.PutUint32(body, uint32(id))
				binary.LittleEndian.PutUint32(body[4:], uint32(seq))
				for j := 8; j < len(body); j++ {
					body[j] = byte(id + seq + j)
				}
				if _, err := c.Write(body); err != nil {
					sendErrors.Add(1)
				} else {
					sent.Add(1)
				}
			}
		}(id)
	}
	wg.Wait()
	time.Sleep(300 * time.Millisecond)
	cancel()
	<-done
	report(t, map[string]any{"test": "parallel_udp", "arch": runtime.GOARCH, "sent": sent.Load(), "send_errors": sendErrors.Load(), "read_errors": readErrors.Load(), "received": received.Load(), "invalid_delivered": invalid.Load(), "seconds": time.Since(start).Seconds(), "stats": s.Stats()})
	if invalid.Load() != 0 {
		t.Fatal(fmt.Errorf("%w: invalid delivered UDP packets: %d", errPayloadIntegrity, invalid.Load()))
	}
	if readErrors.Load() != 0 || received.Load() < 10000 {
		t.Fatal("UDP read error or insufficient delivered packets")
	}
	if s.Stats().RecoveryFailures != 0 {
		t.Fatal("session failed to recover")
	}
}

func TestWintunRecoveryAndCancellation(t *testing.T) {
	requireRunner(t)
	useProductionRegistrar(t, "recovery_registrar_provenance")
	f := newFixture(t, "ours", MinCapacity)
	s := f.io.(*Session)
	f.stopEcho()
	// No sender is running. Publish malformed entries into the actual registered
	// Send memory, then exercise the same detection/unregister/reopen path used
	// for driver corruption. These are deterministic fault injections, reported
	// separately from naturally occurring driver faults in the stress test.
	for _, kind := range []string{"size", "tail", "alignment", "body"} {
		before := s.Stats().Recoveries
		s.mu.Lock()
		r := s.rings
		head := r.head
		binary.LittleEndian.PutUint32(r.send.data()[head:], MaxPacketSize+1)
		switch kind {
		case "size":
			r.send.store(4, (head+8)&(r.send.capacity-1))
		case "tail":
			r.send.store(4, r.send.capacity)
		case "alignment":
			r.send.store(4, head+1)
		case "body":
			p := testPacket()
			p[8] ^= 1 // Real nonzero damage: invalidate the IPv4 header checksum.
			binary.LittleEndian.PutUint32(r.send.data()[head:], uint32(len(p)))
			copy(r.send.data()[head+4:], p)
			r.send.store(4, (head+aligned(uint32(len(p))+4))&(r.send.capacity-1))
		}
		windows.SetEvent(r.readEvent)
		s.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		buf := make([]byte, MaxPacketSize)
		for {
			n, err := s.ReadPacket(ctx, buf)
			if errors.Is(err, context.DeadlineExceeded) {
				break
			}
			if err != nil || n == 0 || !validIP(buf[:n]) {
				cancel()
				t.Fatalf("%s escaped: %d %v", kind, n, err)
			}
			// Windows may emit DNS/IPv6 discovery after a media reconnect.
		}
		cancel()
		// Recovery must finish inside that 500 ms window. Under -race a
		// race-built test registrar missed it (run 39559172829); the release
		// engine registrar above is production's, so the window is unchanged.
		if s.Stats().Recoveries != before+1 {
			t.Fatalf("%s did not recover: %+v", kind, s.Stats())
		}
	}
	f.startEcho(t)
	c := udpSocket(t)
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	_, err := c.Write([]byte("after recovery"))
	must(t, err)
	b := make([]byte, 64)
	n, err := c.Read(b)
	must(t, err)
	if string(b[:n]) != "after recovery" {
		t.Fatal(fmt.Errorf("%w: recovery lost packet integrity", errPayloadIntegrity))
	}
	f.stopEcho()
	f.stopEcho = func() {}
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, MaxPacketSize)
		for {
			if _, err := s.ReadPacket(context.Background(), buf); err != nil {
				done <- err
				return
			}
		}
	}()
	must(t, s.Close())
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close left a blocked reader")
	}
	report(t, map[string]any{"test": "injected_recovery", "arch": runtime.GOARCH, "stats": s.Stats()})
}

func processUsage(t *testing.T) (uint32, uint64) {
	t.Helper()
	var count uint32
	ok, _, err := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessHandleCount").Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&count)))
	if ok == 0 {
		t.Fatal(err)
	}
	type memory struct {
		Size, PageFaults                                                                                                          uint32
		PeakWorkingSet, WorkingSet, QuotaPeakPaged, QuotaPaged, QuotaPeakNonPaged, QuotaNonPaged, Pagefile, PeakPagefile, Private uintptr
	}
	m := memory{}
	m.Size = uint32(unsafe.Sizeof(m))
	ok, _, err = windows.NewLazySystemDLL("psapi.dll").NewProc("GetProcessMemoryInfo").Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&m)), uintptr(m.Size))
	if ok == 0 {
		t.Fatal(err)
	}
	return count, uint64(m.Private)
}

func assertPnPAbsent(t *testing.T, instance string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if !pnpExists(t, instance) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("adapter remains, including non-present PnP records: %s", instance)
}

func pnpExists(t *testing.T, instance string) bool {
	t.Helper()
	// Deliberately omit DIGCF_PRESENT: phantom devices count as leftovers too.
	set, err := windows.SetupDiGetClassDevsEx(&netClass, "SWD\\Wintun", 0, 0, 0, "")
	must(t, err)
	defer set.Close()
	for i := 0; ; i++ {
		dev, err := set.EnumDeviceInfo(i)
		if err == windows.ERROR_NO_MORE_ITEMS {
			return false
		}
		must(t, err)
		id, err := set.DeviceInstanceID(dev)
		must(t, err)
		if strings.EqualFold(id, instance) {
			return true
		}
	}
}

func warmRuntimeThreads() {
	// Go caches OS threads and each Windows M owns six native handles
	// (runtime/os_windows.go: minit and semacreate). Warm that cache before
	// taking the process baseline; do not excuse growth by raising the limit.
	var warm sync.WaitGroup
	ready := make(chan struct{}, 16)
	release := make(chan struct{})
	for i := 0; i < 16; i++ {
		warm.Add(1)
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			defer warm.Done()
			ready <- struct{}{}
			<-release
		}()
	}
	for i := 0; i < 16; i++ {
		<-ready
	}
	close(release)
	warm.Wait()
}

func TestWintunLifetime(t *testing.T) {
	requireRunner(t)
	// Under -race a test-binary registrar spent about 1 s starting each of
	// the 1,000 cycles (run 39564185852); production's is the release engine.
	useProductionRegistrar(t, "lifetime_registrar_provenance")
	a := newAdapter(t, MinCapacity)
	warmRuntimeThreads()
	for i := 0; i < 100; i++ {
		s, err := a.StartSession()
		must(t, err)
		must(t, s.Close())
	}
	debug.FreeOSMemory()
	beforeHandles, beforeBytes := processUsage(t)
	beforeTypes := handleTypes(t)
	start := time.Now()
	// Each cycle starts and retires a registrar process. A stuck cycle fails
	// at the registrar's own start, stop and kill bounds, naming the cycle,
	// instead of at the binary's overall timeout (run 39559172829 hit 5 m
	// under the race detector with no way to tell slow from stuck).
	cycleBound := registrarStartTimeout + registrarStopTimeout + registrarKillTimeout
	var slowest time.Duration
	for i := 0; i < 1000; i++ {
		began := time.Now()
		cycle := make(chan error, 1)
		go func() {
			s, err := a.StartSession()
			if err == nil {
				err = s.Close()
			}
			cycle <- err
		}()
		select {
		case err := <-cycle:
			must(t, err)
		case <-time.After(cycleBound):
			t.Fatalf("session cycle %d did not finish within %s", i, cycleBound)
		}
		slowest = max(slowest, time.Since(began))
		if i%50 == 0 {
			runtime.GC()
		}
		if (i+1)%100 == 0 {
			t.Logf("lifetime progress: %d sessions in %s, slowest cycle %s", i+1, time.Since(start).Round(time.Millisecond), slowest.Round(time.Millisecond))
		}
	}
	debug.FreeOSMemory()
	afterHandles, afterBytes := processUsage(t)
	afterTypes := handleTypes(t)
	report(t, map[string]any{"test": "lifetime", "arch": runtime.GOARCH, "sessions": 1000, "seconds": time.Since(start).Seconds(), "slowest_cycle_ms": slowest.Milliseconds(), "handles_before": beforeHandles, "handles_after": afterHandles, "types_before": beforeTypes, "types_after": afterTypes, "private_bytes_before": beforeBytes, "private_bytes_after": afterBytes})
	if afterHandles > beforeHandles+2 {
		t.Fatal("session handle leak")
	}
	// Go retains heap spans. A 16 MiB bound after GC rejects linear ring leaks
	// while allowing the runtime's heap growth; exact kernel handles are above.
	if afterBytes > beforeBytes+16<<20 {
		t.Fatal("session memory leak")
	}
	instance := a.InstanceID()
	must(t, a.Close())
	assertPnPAbsent(t, instance)
}

func TestWintunAdapterRemoval(t *testing.T) {
	requireRunner(t)
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	owner := newAdapter(t, MinCapacity)
	borrowed, err := Open(owner.config)
	must(t, err)
	defer borrowed.Close()
	s, err := borrowed.StartSession()
	must(t, err)
	if err := RecoverAfterCrash(owner.config); err == nil {
		t.Fatal("crash cleanup accepted a live adapter")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	var reads, writes atomic.Uint64
	go func() {
		buf := make([]byte, MaxPacketSize)
		for {
			if _, err := s.ReadPacket(ctx, buf); err != nil {
				done <- err
				return
			}
			reads.Add(1)
		}
	}()
	writerDone := make(chan error, 1)
	go func() {
		packets := [][]byte{testPacket()}
		for ctx.Err() == nil {
			_, err := s.WriteBatch(packets)
			if err != nil && !errors.Is(err, ErrDisconnected) {
				writerDone <- err
				return
			}
			writes.Add(1)
			runtime.Gosched()
		}
		writerDone <- ctx.Err()
	}()
	c := udpSocket(t)
	defer c.Close()
	for reads.Load() < 10 || writes.Load() < 10 {
		if ctx.Err() != nil {
			t.Fatal("reader/writer did not become busy")
		}
		c.Write([]byte("removal traffic"))
		time.Sleep(time.Millisecond)
	}
	// Real PnP removal while both directions are active, including write-side
	// observation of Receive.Head before the final Send.Tail marker.
	must(t, owner.Close())
	select {
	case err := <-done:
		if !errors.Is(err, ErrAdapterRemoved) {
			t.Fatalf("removal did not wake reader: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("adapter removal left a blocked reader")
	}
	if err := <-writerDone; !errors.Is(err, ErrAdapterRemoved) {
		t.Fatalf("writer removal: %v", err)
	}
	must(t, s.Close())
	runtime.GC()
	if s.Stats().RecoveryFailures != 0 || s.Stats().Recoveries != 0 {
		t.Fatalf("removal counted as recovery: %+v", s.Stats())
	}
	// Count log records, not substrings: the one removal record's joined error
	// text also contains "Wintun adapter removed" (ErrAdapterRemoved).
	if strings.Count(logs.String(), `msg="Wintun adapter removed"`) != 1 || strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("wrong removal logging: %s", logs.String())
	}
	assertPnPAbsent(t, owner.InstanceID())
	report(t, map[string]any{"test": "adapter_removal", "arch": runtime.GOARCH, "stats": s.Stats(), "read_calls": reads.Load(), "write_calls": writes.Load(), "removal_logs": 1})
}

func TestWintunCrashChild(t *testing.T) {
	if os.Getenv("NETSWITCH_WINTUN_CHILD") != "1" {
		t.Skip("child process only")
	}
	requireRunner(t)
	a, err := Create(Config{Name: "NsRingCrashCI", GUID: os.Getenv("NETSWITCH_WINTUN_GUID"), Capacity: MinCapacity})
	must(t, err)
	_, err = a.StartSession()
	must(t, err)
	fmt.Println("READY " + a.InstanceID())
	for {
		time.Sleep(time.Hour)
	}
}

func TestWintunCrash(t *testing.T) {
	requireRunner(t)
	guid, err := windows.GenerateGUID()
	must(t, err)
	exe, err := os.Executable()
	must(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, exe, "-test.run=^TestWintunCrashChild$", "-test.v")
	child.Env = append(os.Environ(), "NETSWITCH_WINTUN_CHILD=1", "NETSWITCH_WINTUN_GUID="+guid.String())
	pipe, err := child.StdoutPipe()
	must(t, err)
	child.Stderr = os.Stderr
	must(t, child.Start())
	t.Cleanup(func() { child.Process.Kill() })
	scan := bufio.NewScanner(pipe)
	instance := ""
	for scan.Scan() {
		if strings.HasPrefix(scan.Text(), "READY ") {
			instance = strings.TrimPrefix(scan.Text(), "READY ")
			break
		}
	}
	if instance == "" {
		t.Fatal("crash child did not create a session")
	}
	must(t, child.Process.Kill())
	if child.Wait() == nil {
		t.Fatal("child did not crash")
	}
	if !pnpExists(t, instance) {
		t.Fatal("crash left no phantom; cleanup was not exercised")
	}
	// A fresh process cannot have queued any DLL orphan sweep. Its cleanup
	// assertion must observe and remove exactly one phantom without loading DLL.
	cleanup := exec.CommandContext(ctx, exe, "-test.run=^TestWintunCrashCleanupChild$", "-test.v")
	cleanup.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cleanup.Env = append(os.Environ(), "NETSWITCH_WINTUN_GUID="+guid.String(), "NETSWITCH_WINTUN_INSTANCE="+instance)
	output, err := cleanup.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("PHANTOM_REMOVED_WITHOUT_DLL")) {
		t.Fatalf("cleanup child: %v\n%s", err, output)
	}
	t.Logf("%s", output)
	assertPnPAbsent(t, instance)
	report(t, map[string]any{"test": "crash", "arch": runtime.GOARCH, "cleanup": "service-recovery hook", "non_present_devices": 0})
}

func TestWintunCrashCleanupChild(t *testing.T) {
	requireRunner(t)
	instance := os.Getenv("NETSWITCH_WINTUN_INSTANCE")
	if instance == "" {
		t.Skip("cleanup child only")
	}
	if dllCache.loaded != nil || !pnpExists(t, instance) {
		t.Fatal("missing phantom or DLL already loaded")
	}
	config := Config{Name: "NsRingCrashCI", GUID: os.Getenv("NETSWITCH_WINTUN_GUID")}
	removed, err := recoverAfterCrash(config)
	must(t, err)
	if removed != 1 {
		t.Fatalf("our hook removed %d devices", removed)
	}
	assertPnPAbsent(t, instance)
	removed, err = recoverAfterCrash(config)
	must(t, err)
	if removed != 0 || dllCache.loaded != nil {
		t.Fatal("clean-system cleanup did work or loaded DLL")
	}
	fmt.Println("PHANTOM_REMOVED_WITHOUT_DLL")
}

func injectRecoveryFault(r *rings) {
	// Send.Head belongs to the reader. Unlike packet bytes and Send.Tail, the
	// driver cannot overwrite it with discovery traffic after a reconnect.
	// The normal ReadBatch corruption check must detect it and request recovery.
	r.send.store(0, r.send.capacity)
}

func TestWintunRecoveryLeak(t *testing.T) {
	requireRunner(t)
	a := newAdapter(t, 0)
	s, err := a.StartSession()
	must(t, err)
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	readerErr := make(chan error, 1)
	go func() {
		defer close(done)
		buf := make([]byte, MaxPacketSize)
		for ctx.Err() == nil {
			if _, err := s.ReadPacket(ctx, buf); err != nil {
				readerErr <- err
				return
			}
		}
	}()
	defer func() { cancel(); <-done }()
	iteration := 0
	recoverOne := func() {
		iteration++
		started := time.Now()
		before := s.Stats()
		// A native read wait holds mu.RLock; wake it before taking the writer lock.
		windows.SetEvent(s.wake)
		s.mu.Lock()
		r := s.rings
		injectRecoveryFault(r)
		windows.SetEvent(r.readEvent)
		windows.ResetEvent(s.wake)
		s.mu.Unlock()
		deadline := time.NewTimer(3 * time.Second)
		defer deadline.Stop()
		for {
			select {
			case e := <-s.Events():
				if e.Kind == "recovered" {
					if stats := s.Stats(); stats.Corruptions != before.Corruptions+1 || stats.Recoveries != before.Recoveries+1 {
						t.Fatalf("recovery %d: before=%+v after=%+v", iteration, before, stats)
					}
					return
				}
				if e.Kind == "failed" {
					t.Fatal(e.Err)
				}
			case <-deadline.C:
				t.Logf("recovery %d timed out after %v: recovering=%v closed=%v before=%+v after=%+v", iteration, time.Since(started), s.recovering.Load(), s.closed.Load(), before, s.Stats())
				if s.mu.TryRLock() {
					if r := s.rings; r != nil {
						t.Logf("current ring: head=%d tail=%d", r.send.load(0), r.send.load(4))
					}
					t.Logf("session error: %v", s.err)
					s.mu.RUnlock()
				} else {
					t.Log("session mutex held exclusively")
				}
				select {
				case err := <-readerErr:
					t.Logf("reader exited: %v", err)
				default:
				}
				stacks := make([]byte, 64<<10)
				t.Logf("goroutines:\n%s", stacks[:runtime.Stack(stacks, true)])
				t.Fatal("injected recovery did not complete")
			}
		}
	}
	for i := 0; i < 8; i++ {
		recoverOne()
	}
	warmRuntimeThreads()
	debug.FreeOSMemory()
	beforeHandles, beforeBytes := processUsage(t)
	beforeTypes := handleTypes(t)
	beforeThreads, _ := runtime.ThreadCreateProfile(nil)
	beforeDevices := pnpDevices(t)
	start := time.Now()
	for i := 0; i < 32; i++ {
		recoverOne()
	}
	debug.FreeOSMemory()
	afterHandles, afterBytes := processUsage(t)
	afterTypes := handleTypes(t)
	afterThreads, _ := runtime.ThreadCreateProfile(nil)
	afterDevices := pnpDevices(t)
	report(t, map[string]any{"test": "recovery_leak", "arch": runtime.GOARCH, "measured_recoveries": 32, "seconds": time.Since(start).Seconds(), "handles_before": beforeHandles, "handles_after": afterHandles, "private_bytes_before": beforeBytes, "private_bytes_after": afterBytes, "pnp_before": beforeDevices, "pnp_after": afterDevices, "types_before": beforeTypes, "types_after": afterTypes, "go_threads_before": beforeThreads, "go_threads_after": afterThreads})
	if afterHandles > beforeHandles+2 || afterBytes > beforeBytes+16<<20 || !slices.Equal(beforeDevices, afterDevices) {
		t.Fatalf("recovery leak: handles %d -> %d, bytes %d -> %d, devices %v -> %v", beforeHandles, afterHandles, beforeBytes, afterBytes, beforeDevices, afterDevices)
	}
	if s.Stats().Recoveries != 40 || s.Stats().RecoveryFailures != 0 || time.Since(start) < 7*time.Second {
		t.Fatalf("missing recoveries or backoff: %+v in %v", s.Stats(), time.Since(start))
	}
}

func pnpDevices(t *testing.T) []string {
	t.Helper()
	set, err := windows.SetupDiGetClassDevsEx(&netClass, "SWD\\Wintun", 0, 0, 0, "")
	must(t, err)
	defer set.Close()
	var ids []string
	for i := 0; ; i++ {
		dev, err := set.EnumDeviceInfo(i)
		if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			break
		}
		must(t, err)
		id, err := set.DeviceInstanceID(dev)
		must(t, err)
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func handleTypes(t *testing.T) map[uint32]int {
	t.Helper()
	// ProcessHandleInformation: two pointer-sized header fields followed by
	// PROCESS_HANDLE_TABLE_ENTRY_INFO (three pointers and four ULONGs).
	data := make([]byte, 1<<20)
	var used uint32
	must(t, windows.NtQueryInformationProcess(windows.CurrentProcess(), windows.ProcessHandleInformation, unsafe.Pointer(&data[0]), uint32(len(data)), &used))
	count := binary.LittleEndian.Uint64(data[:8])
	if count > uint64((len(data)-16)/40) {
		t.Fatal("invalid process handle snapshot")
	}
	types := map[uint32]int{}
	for i := uint64(0); i < count; i++ {
		types[binary.LittleEndian.Uint32(data[16+i*40+28:])]++
	}
	return types
}
