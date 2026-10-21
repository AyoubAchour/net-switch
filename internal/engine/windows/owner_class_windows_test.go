//go:build windows

package winengine

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/winclock"
	"golang.org/x/sys/windows"
)

var spinSink atomic.Uint64

type tcpTableRow struct {
	state uint32
	local netip.AddrPort
	peer  netip.AddrPort
	pid   uint32
}

func tcpTableRows(t *testing.T, family, class uint32) []tcpTableRow {
	t.Helper()
	b, err := readOwnerTable(context.Background(), tcpTable, family, class)
	if err != nil {
		t.Fatal(err)
	}
	stride := 24
	if family == windows.AF_INET6 {
		stride = 56
	}
	raw, err := ownerRows(b, 4, stride)
	if err != nil {
		t.Fatal(err)
	}
	rows := make([]tcpTableRow, 0, len(raw))
	for _, r := range raw {
		if family == windows.AF_INET6 {
			rows = append(rows, tcpTableRow{binary.LittleEndian.Uint32(r[48:]),
				netip.AddrPortFrom(netip.AddrFrom16([16]byte(r[:16])), binary.BigEndian.Uint16(r[20:])),
				netip.AddrPortFrom(netip.AddrFrom16([16]byte(r[24:40])), binary.BigEndian.Uint16(r[44:])),
				binary.LittleEndian.Uint32(r[52:])})
			continue
		}
		rows = append(rows, tcpTableRow{binary.LittleEndian.Uint32(r),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte(r[4:8])), binary.BigEndian.Uint16(r[8:])),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte(r[12:16])), binary.BigEndian.Uint16(r[16:])),
			binary.LittleEndian.Uint32(r[20:])})
	}
	return rows
}

// The owner read uses TCP_TABLE_OWNER_PID_CONNECTIONS. Prove on the real OS
// that it still holds SYN_SENT rows with their owner, and that what it leaves
// out compared with OWNER_PID_ALL is listeners only.
func TestOwnerConnectionsClassKeepsSynSent(t *testing.T) {
	hosted(t)
	pid := uint32(os.Getpid())
	for _, scenario := range []struct {
		network, loopback string
		family            uint32
		blackhole         string
	}{
		{"tcp4", "127.0.0.1", windows.AF_INET, "192.0.2.1:9"},
		{"tcp6", "::1", windows.AF_INET6, "[2001:db8::1]:9"},
	} {
		t.Run(scenario.network, func(t *testing.T) {
			listener, err := net.Listen(scenario.network, net.JoinHostPort(scenario.loopback, "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			listening := listener.Addr().(*net.TCPAddr).AddrPort()
			closed, err := net.Listen(scenario.network, net.JoinHostPort(scenario.loopback, "0"))
			if err != nil {
				t.Fatal(err)
			}
			refused := closed.Addr().String()
			closed.Close()
			// Windows answers a refused loopback connect by retransmitting the
			// SYN for about two seconds; a TEST-NET peer never answers. Either
			// keeps a SYN_SENT socket long enough to read it.
			var synSent *tcpTableRow
			for _, target := range []string{refused, scenario.blackhole} {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				done := make(chan struct{})
				go func() {
					defer close(done)
					if conn, err := (&net.Dialer{}).DialContext(ctx, scenario.network, target); err == nil {
						conn.Close()
					}
				}()
				peer := netip.MustParseAddrPort(target)
				for deadline := time.Now().Add(1500 * time.Millisecond); synSent == nil && time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
					for _, row := range tcpTableRows(t, scenario.family, tcpOwnerPIDConnections) {
						if row.peer.Port() == peer.Port() && row.peer.Addr().Unmap() == peer.Addr().Unmap() && row.state == 3 {
							synSent = &row
							break
						}
					}
				}
				cancel()
				<-done
				if synSent != nil {
					t.Logf("SYN_SENT row through %s: %+v", target, *synSent)
					break
				}
				t.Logf("no SYN_SENT row seen through %s", target)
			}
			switch {
			case synSent != nil && synSent.pid != pid:
				t.Fatalf("SYN_SENT row has the wrong owner: %+v", *synSent)
			case synSent == nil && scenario.family == windows.AF_INET:
				t.Fatal("OWNER_PID_CONNECTIONS has no SYN_SENT row owned by this process")
			case synSent == nil:
				// Hosted x64 job 119275809836: a refused [::1] connect fails at
				// once and the runner has no IPv6 route, so no IPv6 socket stays
				// in SYN_SENT. The class is family-independent; IPv6 SYN lookups
				// through it are exercised by the acceptance suite's IPv6 TCP
				// cases through the TUN.
				t.Log("no IPv6 SYN_SENT socket could be held on this runner")
			}
			client, err := net.Dial(scenario.network, listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			established := client.LocalAddr().(*net.TCPAddr).AddrPort()
			if !slices.ContainsFunc(tcpTableRows(t, scenario.family, tcpOwnerPIDConnections), func(row tcpTableRow) bool {
				return row.state == 5 && row.pid == pid && row.local.Port() == established.Port() && row.peer.Port() == listening.Port()
			}) {
				t.Fatalf("OWNER_PID_CONNECTIONS lacks this process's ESTABLISHED client %v", established)
			}
			all := tcpTableRows(t, scenario.family, tcpOwnerPIDAll)
			connections := tcpTableRows(t, scenario.family, tcpOwnerPIDConnections)
			if !slices.ContainsFunc(all, func(row tcpTableRow) bool { return row.state == 2 && row.local.Port() == listening.Port() }) {
				t.Fatalf("OWNER_PID_ALL lacks this test's listener on %v", listening)
			}
			states := map[uint32]int{}
			for _, row := range connections {
				states[row.state]++
				if row.state == 2 {
					t.Fatalf("OWNER_PID_CONNECTIONS returned a listener: %+v", row)
				}
			}
			allStates := map[uint32]int{}
			for _, row := range all {
				allStates[row.state]++
			}
			t.Logf("rows by state: connections=%v all=%v", states, allStates)
		})
	}
}

// Measure owner-table reads at 13,700-14,800 TCP rows, the x64 OS port limit
// where lookups ran out of the 50 ms bound: the old class (OWNER_PID_ALL) and
// the new one (OWNER_PID_CONNECTIONS), interleaved on the same rows, idle and
// with every processor busy. It reports; the capacity case is the gate.
func TestOwnerReadTimeAtPortLimit(t *testing.T) {
	hosted(t)
	if os.Getenv("NETSWITCH_OWNER_READ_GATE") != "1" {
		t.Skip("runs in the focused capacity job")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var mu sync.Mutex
	var conns []net.Conn
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			conn.(*net.TCPConn).SetLinger(0)
			conn.Close()
		}
	}()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}()
	// Earlier tests' TIME_WAIT rows expire during a phase (x64 job
	// 119321529600 fell from 13,622 to 13,469 rows), so top up to the middle
	// of the range before each phase, not once.
	fill := func() {
		rows, _ := nativeTCPRowCounts(t)
		for pairs := 0; rows < 14250; pairs++ {
			conn, err := net.Dial("tcp4", listener.Addr().String())
			if err != nil {
				t.Fatalf("after %d pairs (%d rows): %v", pairs, rows, err)
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			if pairs%250 == 0 || rows > 13850 {
				rows, _ = nativeTCPRowCounts(t)
			}
		}
	}
	type sample struct{ read, index time.Duration }
	type result struct {
		Class                  uint32
		Reads                  int
		RowsMin, RowsMax       int
		ReadP50US, ReadP95US   int64
		ReadMaxUS, IndexP50US  int64
		IndexP95US, TotalP95US int64
		ReadMeanUS             int64
	}
	measure := func(class uint32, scratch *[]uint64, into *[]sample, rows *[2]int) {
		start := winclock.Now()
		b, err := readOwnerTableInto(context.Background(), tcpTable, windows.AF_INET, class, scratch)
		read := winclock.Since(start)
		if err != nil {
			t.Fatal(err)
		}
		indexStart := winclock.Now()
		index := tcpIndex{v4: make(map[[12]byte]tcpCandidates, len(b)/24)}
		if err := parseTCP(b, false, &index); err != nil {
			t.Fatal(err)
		}
		*into = append(*into, sample{read, winclock.Since(indexStart)})
		count := int(binary.LittleEndian.Uint32(b))
		rows[0], rows[1] = min(rows[0], count), max(rows[1], count)
	}
	summarize := func(class uint32, samples []sample, rows [2]int) result {
		reads := make([]time.Duration, len(samples))
		indexes := make([]time.Duration, len(samples))
		totals := make([]time.Duration, len(samples))
		var sum time.Duration
		for i, s := range samples {
			reads[i], indexes[i], totals[i] = s.read, s.index, s.read+s.index
			sum += s.read
		}
		slices.Sort(reads)
		slices.Sort(indexes)
		slices.Sort(totals)
		at := func(d []time.Duration, p int) int64 { return d[(p*len(d)+99)/100-1].Microseconds() }
		return result{class, len(samples), rows[0], rows[1], at(reads, 50), at(reads, 95), reads[len(reads)-1].Microseconds(),
			at(indexes, 50), at(indexes, 95), at(totals, 95), (sum / time.Duration(len(samples))).Microseconds()}
	}
	phase := func(name string) {
		fill()
		var oldScratch, newScratch []uint64
		var oldSamples, newSamples []sample
		oldRows, newRows := [2]int{1 << 30, 0}, [2]int{1 << 30, 0}
		for range 150 {
			measure(tcpOwnerPIDAll, &oldScratch, &oldSamples, &oldRows)
			measure(tcpOwnerPIDConnections, &newScratch, &newSamples, &newRows)
		}
		total, timeWait := nativeTCPRowCounts(t)
		out, _ := json.Marshal(map[string]any{"phase": name, "before": summarize(tcpOwnerPIDAll, oldSamples, oldRows),
			"after": summarize(tcpOwnerPIDConnections, newSamples, newRows), "rowsBothFamilies": total, "timeWait": timeWait,
			"cpus": runtime.NumCPU(), "gomaxprocs": runtime.GOMAXPROCS(0)})
		t.Logf("WINDOWS OWNER READ TIME %s", out)
		if oldRows[0] < 13700 || oldRows[1] > 14800 {
			t.Errorf("%s: measured at %d-%d IPv4 rows, outside 13,700-14,800", name, oldRows[0], oldRows[1])
		}
	}
	phase("idle")
	// Every processor busy, as at the port limit, where the engine, the
	// clients and the servers all compete with the read.
	stop := make(chan struct{})
	var spinning sync.WaitGroup
	for range runtime.NumCPU() {
		spinning.Add(1)
		go func() {
			defer spinning.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for i := 0; i < 1<<16; i++ {
					spinSink.Add(1)
				}
			}
		}()
	}
	phase("busy")
	close(stop)
	spinning.Wait()
}
