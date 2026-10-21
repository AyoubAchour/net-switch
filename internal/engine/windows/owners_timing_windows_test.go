//go:build windows

package winengine

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"runtime"
	"slices"
	"testing"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"golang.org/x/sys/windows"
)

// Keep an independent QPC measurement beside the old Go clock on exactly the
// same cold calls. The pinned Go runtime reads coarse interrupt time on Windows.
func lookupPerformanceClock(t *testing.T) (func() int64, int64) {
	t.Helper()
	dll := windows.NewLazySystemDLL("kernel32.dll")
	counter, frequency := dll.NewProc("QueryPerformanceCounter"), dll.NewProc("QueryPerformanceFrequency")
	var hz int64
	if ok, _, err := frequency.Call(uintptr(unsafe.Pointer(&hz))); ok == 0 || hz <= 0 {
		t.Fatalf("QueryPerformanceFrequency: %d %v", hz, err)
	}
	return func() int64 {
		var ticks int64
		if ok, _, err := counter.Call(uintptr(unsafe.Pointer(&ticks))); ok == 0 {
			t.Fatalf("QueryPerformanceCounter: %v", err)
		}
		return ticks
	}, hz
}

func nativeTCPRowCounts(t *testing.T) (total, timeWait int) {
	t.Helper()
	for _, family := range []uint32{windows.AF_INET, windows.AF_INET6} {
		count, waiting := nativeTCPFamilyRowCounts(t, family)
		total, timeWait = total+count, timeWait+waiting
	}
	return
}

func nativeTCPFamilyRowCounts(t *testing.T, family uint32) (total, timeWait int) {
	t.Helper()
	b, err := readOwnerTable(context.Background(), tcpTable, family, tcpOwnerPIDAll)
	if err != nil {
		t.Fatal(err)
	}
	stride, state := 24, 0
	if family == windows.AF_INET6 {
		stride, state = 56, 48
	}
	rows, err := ownerRows(b, 4, stride)
	if err != nil {
		t.Fatal(err)
	}
	total = len(rows)
	for _, row := range rows {
		if binary.LittleEndian.Uint32(row[state:]) == 11 { // MIB_TCP_STATE_TIME_WAIT.
			timeWait++
		}
	}
	return
}

// This is the latency gate, separate from burst attribution. Every sample
// creates a new native socket and performs a cold table lookup at about 2,000
// actual kernel rows, including listeners and TIME_WAIT owned by other tests.
func TestOwnerSteadyColdTiming(t *testing.T) {
	hosted(t)
	if os.Getenv("NETSWITCH_LOOKUP_GATE") != "1" {
		t.Skip("timing runs separately from race instrumentation")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	closePair := func(client, server net.Conn) {
		// Cleanup is outside the measurement. Abort both sides so this
		// fixture cannot accumulate TIME_WAIT or poison the next phase.
		client.(*net.TCPConn).SetLinger(0)
		server.(*net.TCPConn).SetLinger(0)
		client.Close()
		server.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	openPair := func() (net.Conn, net.Conn) {
		t.Helper()
		client, err := (&net.Dialer{}).DialContext(ctx, "tcp4", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		server, err := listener.Accept()
		if err != nil {
			client.(*net.TCPConn).SetLinger(0)
			client.Close()
			t.Fatal(err)
		}
		return client, server
	}
	baseline, timeWait := nativeTCPRowCounts(t)
	if baseline > 2098 {
		t.Fatalf("latency fixture already has %d TCP rows (%d TIME_WAIT); cannot measure at 2000", baseline, timeWait)
	}
	var held [][2]net.Conn
	defer func() {
		for _, pair := range held {
			closePair(pair[0], pair[1])
		}
	}()
	for range max(0, (2000-baseline-2)/2) {
		client, server := openPair()
		held = append(held, [2]net.Conn{client, server})
	}
	owners := NewOwners()
	counter, frequency := lookupPerformanceClock(t)
	const count = 500
	var samples, preciseSamples []time.Duration
	var clockDifferences [][2]int64
	minRows, maxRows := uint64(^uint64(0)), uint64(0)
	for range count {
		client, server := openPair()
		tuple := platform.Tuple{Source: client.LocalAddr().(*net.TCPAddr).AddrPort(), Destination: client.RemoteAddr().(*net.TCPAddr).AddrPort()}
		// Even if Windows immediately reuses a reset tuple, no sample can
		// become a warm tuple-cache hit. Process metadata and native buffer
		// reuse are production behavior and remain enabled.
		owners.snapshot[0].Store(nil)
		started := time.Now()
		preciseStarted := counter()
		owner, err := owners.TCP(ctx, tuple)
		preciseElapsed := time.Duration((counter() - preciseStarted) * int64(time.Second) / frequency)
		elapsed := time.Since(started)
		if elapsed >= 5*time.Millisecond || preciseElapsed >= 5*time.Millisecond {
			clockDifferences = append(clockDifferences, [2]int64{elapsed.Microseconds(), preciseElapsed.Microseconds()})
		}
		snapshot := owners.snapshot[0].Load()
		if err != nil || owner.PID != uint32(os.Getpid()) || snapshot == nil {
			closePair(client, server)
			t.Fatalf("cold lookup did not identify the new socket: %+v %v", owner, err)
		}
		// Count the unrelated family after stopping the lookup clock, while
		// the measured socket is still held. IPv4's count comes from the
		// exact snapshot that served the timed call; TIME_WAIT is included.
		other, _ := nativeTCPFamilyRowCounts(t, windows.AF_INET6)
		rows := snapshot.rawRows + uint64(other)
		closePair(client, server)
		if rows < 1950 || rows > 2100 {
			t.Fatalf("latency sample had %d actual TCP rows, outside 1950–2100; baseline=%d TIME_WAIT=%d", rows, baseline, timeWait)
		}
		minRows, maxRows = min(minRows, rows), max(maxRows, rows)
		samples = append(samples, elapsed)
		preciseSamples = append(preciseSamples, preciseElapsed)
	}
	slices.Sort(samples)
	slices.Sort(preciseSamples)
	p95 := samples[(95*count+99)/100-1]
	preciseP95 := preciseSamples[(95*count+99)/100-1]
	histogram, _ := json.Marshal(owners.Stats())
	t.Logf("WINDOWS OWNER LATENCY samples=%d found=%d raw_rows_min=%d raw_rows_max=%d baseline=%d baseline_timewait=%d p95_us=%d old_go_p95_us=%d processors=%d cpus=%d histogram=%s",
		count, len(samples), minRows, maxRows, baseline, timeWait, preciseP95.Microseconds(), p95.Microseconds(), runtime.GOMAXPROCS(0), runtime.NumCPU(), histogram)
	t.Logf("WINDOWS OWNER CLOCK COMPARISON samples=%d frequency=%d go_p95_us=%d qpc_p95_us=%d go_zero_samples=%d qpc_zero_samples=%d slow_pairs_go_qpc_us=%v",
		count, frequency, p95.Microseconds(), preciseP95.Microseconds(),
		slices.IndexFunc(samples, func(d time.Duration) bool { return d > 0 }),
		slices.IndexFunc(preciseSamples, func(d time.Duration) bool { return d > 0 }), clockDifferences)
	if preciseP95 >= 5*time.Millisecond {
		t.Errorf("high-resolution cold owner latency at 2000 rows: p95=%s, requires under 5ms", preciseP95)
	}
	t.Logf("OLD GO-CLOCK LATENCY CHECK would_pass=%t", p95 < 5*time.Millisecond)
}

func TestSnapshotFreshnessIgnoresCoarseClockTicks(t *testing.T) {
	published := time.Second
	snapshot := &ownerSnapshot{at: published}
	// All these instants fit inside one 16 ms Go-clock tick. Expiry must follow
	// the precise publication age, and a newer required generation must win.
	for _, test := range []struct {
		age, after time.Duration
		want       bool
	}{
		{0, 0, true}, {4999 * time.Microsecond, 0, true},
		{5 * time.Millisecond, 0, false}, {15 * time.Millisecond, 0, false},
		{0, published, false},
	} {
		if got := freshSnapshot(snapshot, test.after, published+test.age); got != test.want {
			t.Fatalf("age=%v required=%v fresh=%t want=%t", test.age, test.after, got, test.want)
		}
	}
}
