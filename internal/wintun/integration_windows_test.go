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
	"net"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

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

type batchIO interface {
	ReadBatch(context.Context, [][]byte, []int) (int, error)
	WriteBatch([][]byte) (int, error)
	Close() error
}

type fixture struct {
	a         *Adapter
	io        batchIO
	stopEcho  func()
	faults    atomic.Uint64
	faultMu   sync.Mutex
	lastFault error
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
	t.Cleanup(func() { must(t, a.Close()) })
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
	s, err := a.StartSession()
	must(t, err)
	return s
}

func newFixture(t *testing.T, mode string, capacity uint32) *fixture {
	t.Helper()
	f := &fixture{a: newAdapter(t, capacity)}
	f.io = startIO(t, f.a, mode)
	f.startEcho(t)
	t.Cleanup(func() { f.stopEcho(); must(t, f.io.Close()) })
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
		for {
			n, err := f.io.ReadBatch(ctx, buffers, sizes)
			if err != nil {
				if ctx.Err() == nil {
					f.recordFault(err)
					t.Logf("echo read: %v", err)
				}
				return
			}
			out := make([][]byte, 0, n)
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
	mu                                    sync.RWMutex
	readMu, writeMu                       sync.Mutex
	h                                     uintptr
	event, stop, cancelEvent              windows.Handle
	receive, release, allocate, send, end uintptr
	closed                                atomic.Bool
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

func (s *dllSession) ReadBatch(ctx context.Context, buffers [][]byte, sizes []int) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	cancelEvent := s.cancelEvent
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { windows.SetEvent(cancelEvent); close(done) })
	defer func() {
		if !stop() {
			<-done
			windows.ResetEvent(cancelEvent)
		}
	}()
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
			syscall.SyscallN(s.release, s.h, p)
			sizes[i] = int(size)
			if i == len(buffers)-1 {
				return len(buffers), nil
			}
		}
		_, err := windows.WaitForMultipleObjects([]windows.Handle{s.stop, s.event, cancelEvent}, false, windows.INFINITE)
		if err != nil {
			return 0, err
		}
	}
}

func (s *dllSession) WriteBatch(packets [][]byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	n := 0
	for _, b := range packets {
		p, _, e := syscall.SyscallN(s.allocate, s.h, uintptr(len(b)))
		if p == 0 {
			if e == windows.ERROR_BUFFER_OVERFLOW {
				continue
			}
			return n, e
		}
		nativeCopy.Call(p, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
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
	Arch           string  `json:"arch"`
	Mode           string  `json:"mode"`
	RoundTrips     int     `json:"round_trips"`
	Over50MS       int     `json:"over_50_ms"`
	TimeoutRescues int     `json:"timeout_rescues"`
	MaxMS          float64 `json:"max_ms"`
	P50US          float64 `json:"p50_us"`
	P95US          float64 `json:"p95_us"`
	P99US          float64 `json:"p99_us"`
}

func TestWintunPingPong(t *testing.T) {
	requireRunner(t)
	for _, mode := range []string{"dll", "ours"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, mode, 0)
			c := udpSocket(t)
			defer c.Close()
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
						t.Fatal("ping-pong payload corruption")
					}
					break
				}
				d := elapsed(start)
				timings = append(timings, d)
				if d > 50*time.Millisecond {
					result.Over50MS++
				}
				if float64(d)/float64(time.Millisecond) > result.MaxMS {
					result.MaxMS = float64(d) / float64(time.Millisecond)
				}
			}
			sort.Slice(timings, func(i, j int) bool { return timings[i] < timings[j] })
			result.P50US = float64(timings[len(timings)/2]) / 1000
			result.P95US = float64(timings[len(timings)*95/100]) / 1000
			result.P99US = float64(timings[len(timings)*99/100]) / 1000
			report(t, result)
			if mode == "ours" && result.Over50MS != 0 {
				t.Errorf("own session had %d round trips over 50 ms", result.Over50MS)
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
	var received, invalid atomic.Uint64
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
					invalid.Add(1)
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
	report(t, map[string]any{"test": "parallel_udp", "arch": runtime.GOARCH, "sent": sent.Load(), "send_errors": sendErrors.Load(), "received": received.Load(), "invalid_delivered": invalid.Load(), "seconds": time.Since(start).Seconds(), "stats": s.Stats()})
	if invalid.Load() != 0 || received.Load() < 10000 {
		t.Fatal("invalid or insufficient delivered packets")
	}
	if s.Stats().RecoveryFailures != 0 {
		t.Fatal("session failed to recover")
	}
}

func TestWintunRecoveryAndCancellation(t *testing.T) {
	requireRunner(t)
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
			binary.LittleEndian.PutUint32(r.send.data()[head:], 20)
			clear(r.send.data()[head+4 : head+24])
			r.send.store(4, (head+24)&(r.send.capacity-1))
		}
		windows.SetEvent(r.readEvent)
		s.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
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
		t.Fatal("recovery lost packet integrity")
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

func TestWintunLifetime(t *testing.T) {
	requireRunner(t)
	a := newAdapter(t, MinCapacity)
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
	for i := 0; i < 100; i++ {
		s, err := a.StartSession()
		must(t, err)
		must(t, s.Close())
	}
	debug.FreeOSMemory()
	beforeHandles, beforeBytes := processUsage(t)
	beforeTypes := handleTypes(t)
	start := time.Now()
	for i := 0; i < 1000; i++ {
		s, err := a.StartSession()
		must(t, err)
		must(t, s.Close())
		if i%50 == 0 {
			runtime.GC()
		}
	}
	debug.FreeOSMemory()
	afterHandles, afterBytes := processUsage(t)
	afterTypes := handleTypes(t)
	report(t, map[string]any{"test": "lifetime", "arch": runtime.GOARCH, "sessions": 1000, "seconds": time.Since(start).Seconds(), "handles_before": beforeHandles, "handles_after": afterHandles, "types_before": beforeTypes, "types_after": afterTypes, "private_bytes_before": beforeBytes, "private_bytes_after": afterBytes})
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
	go func() {
		buf := make([]byte, MaxPacketSize)
		for {
			if _, err := s.ReadPacket(ctx, buf); err != nil {
				done <- err
				return
			}
		}
	}()
	// The owner removes an adapter while another reference has a blocked read.
	// This exercises the driver's real PnP disconnection path.
	must(t, owner.Close())
	select {
	case err := <-done:
		if err == nil || errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("removal did not wake reader: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("adapter removal left a blocked reader")
	}
	must(t, s.Close())
	assertPnPAbsent(t, owner.InstanceID())
	report(t, map[string]any{"test": "adapter_removal", "arch": runtime.GOARCH, "stats": s.Stats()})
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
	must(t, RecoverAfterCrash(Config{Name: "NsRingCrashCI", GUID: guid.String(), Capacity: MinCapacity}))
	assertPnPAbsent(t, instance)
	report(t, map[string]any{"test": "crash", "arch": runtime.GOARCH, "cleanup": "service-recovery hook", "non_present_devices": 0})
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

