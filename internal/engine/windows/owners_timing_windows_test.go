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

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"golang.org/x/sys/windows"
)

func nativeTCPRowCounts(t *testing.T) (total, timeWait int) {
	t.Helper()
	for _, family := range []uint32{windows.AF_INET, windows.AF_INET6} {
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
		total += len(rows)
		for _, row := range rows {
			if binary.LittleEndian.Uint32(row[state:]) == 11 { // MIB_TCP_STATE_TIME_WAIT.
				timeWait++
			}
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
	const count = 500
	var samples []time.Duration
	minRows, maxRows := uint64(^uint64(0)), uint64(0)
	for range count {
		client, server := openPair()
		tuple := platform.Tuple{Source: client.LocalAddr().(*net.TCPAddr).AddrPort(), Destination: client.RemoteAddr().(*net.TCPAddr).AddrPort()}
		// Even if Windows immediately reuses a reset tuple, no sample can
		// become a warm tuple-cache hit. Process metadata and native buffer
		// reuse are production behavior and remain enabled.
		owners.snapshot.Store(nil)
		started := time.Now()
		owner, err := owners.TCP(ctx, tuple)
		elapsed := time.Since(started)
		snapshot := owners.snapshot.Load()
		closePair(client, server)
		if err != nil || owner.PID != uint32(os.Getpid()) || snapshot == nil {
			t.Fatalf("cold lookup did not identify the new socket: %+v %v", owner, err)
		}
		rows := snapshot.rawRows
		if rows < 1950 || rows > 2100 {
			t.Fatalf("latency sample had %d actual TCP rows, outside 1950–2100; baseline=%d TIME_WAIT=%d", rows, baseline, timeWait)
		}
		minRows, maxRows = min(minRows, rows), max(maxRows, rows)
		samples = append(samples, elapsed)
	}
	slices.Sort(samples)
	p95 := samples[(95*count+99)/100-1]
	histogram, _ := json.Marshal(owners.Stats())
	t.Logf("WINDOWS OWNER LATENCY samples=%d found=%d raw_rows_min=%d raw_rows_max=%d baseline=%d baseline_timewait=%d p95_us=%d processors=%d cpus=%d histogram=%s",
		count, len(samples), minRows, maxRows, baseline, timeWait, p95.Microseconds(), runtime.GOMAXPROCS(0), runtime.NumCPU(), histogram)
	if p95 >= 5*time.Millisecond {
		t.Fatalf("cold owner latency at 2000 rows: p95=%s, requires under 5ms", p95)
	}
}
