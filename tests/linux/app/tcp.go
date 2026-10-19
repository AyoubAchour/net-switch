//go:build linux

package app

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/wire"
)

// Attempt is one TCP connection to a whoami server.
type Attempt struct {
	I         int     `json:"i"`
	To        string  `json:"to"`
	Seen      string  `json:"seen,omitempty"`
	Err       string  `json:"err,omitempty"`
	ConnectMS float64 `json:"connectMs"`
	TotalMS   float64 `json:"totalMs"`
	Port      int     `json:"port,omitempty"`
	At        int64   `json:"at"` // Unix ms when it started
	Retries   int     `json:"retries,omitempty"`
	// Connected: the handshake completed (an engine that completes it before
	// its own dial succeeds shows connections that then fail).
	Connected bool `json:"connected,omitempty"`
}

// TCPResult is the tcp mode's answer.
type TCPResult struct {
	Count     int            `json:"count"`
	OK        int            `json:"ok"`
	Errors    map[string]int `json:"errors"`
	Seen      map[string]int `json:"seen"`
	Connect   Stats          `json:"connectMs"`
	Total     Stats          `json:"totalMs"`
	FailedMS  Stats          `json:"failedMs"`
	WallMS    float64        `json:"wallMs"`
	Attempts  []Attempt      `json:"attempts"`
	StartedAt int64          `json:"startedAt"`
}

func whoamiOnce(i int, to netip.AddrPort, local netip.AddrPort, dev string, timeout time.Duration) Attempt {
	a := Attempt{I: i, To: to.String(), At: nowMS()}
	d := net.Dialer{Timeout: timeout, Control: socketOptions(dev)}
	if local.IsValid() {
		d.LocalAddr = net.TCPAddrFromAddrPort(local)
	}
	start := time.Now()
	conn, err := d.Dial("tcp", to.String())
	a.ConnectMS = msSince(start)
	if err != nil {
		a.Err = Code(err)
		a.TotalMS = a.ConnectMS
		return a
	}
	defer conn.Close()
	a.Connected = true
	if ap, err := netip.ParseAddrPort(conn.LocalAddr().String()); err == nil {
		a.Port = int(ap.Port())
	}
	_ = conn.SetDeadline(start.Add(timeout))
	data, err := io.ReadAll(io.LimitReader(conn, 256))
	a.TotalMS = msSince(start)
	a.Seen = strings.TrimSpace(string(data))
	switch {
	case err != nil:
		a.Err = Code(err)
	case a.Seen == "":
		a.Err = "EMPTY"
	}
	return a
}

func summariseAttempts(attempts []Attempt, wall time.Duration, started int64) TCPResult {
	r := TCPResult{Count: len(attempts), Errors: map[string]int{}, Seen: map[string]int{}, Attempts: attempts, StartedAt: started}
	var connect, total, failed []float64
	for _, a := range attempts {
		if a.Err != "" {
			r.Errors[a.Err]++
			failed = append(failed, a.TotalMS)
			continue
		}
		r.OK++
		tally(r.Seen, a.Seen)
		connect = append(connect, a.ConnectMS)
		total = append(total, a.TotalMS)
	}
	r.Connect, r.Total, r.FailedMS = Summarise(connect), Summarise(total), Summarise(failed)
	r.WallMS = round(float64(wall.Microseconds()) / 1000)
	return r
}

func runTCP(args []string) (any, error) {
	fs := flag.NewFlagSet("tcp", flag.ContinueOnError)
	to := fs.String("to", "", "whoami servers, ip:port[,ip:port...], used in turn")
	count := fs.Int("count", 1, "connections")
	concurrency := fs.Int("concurrency", 1, "connections at once")
	timeout := fs.Int("timeout", 5000, "ms per connection")
	gap := fs.Int("gap", 0, "ms between connections (concurrency 1)")
	localAddr := fs.String("local-addr", "", "source address to bind")
	bindDev := fs.String("bind-dev", "", "interface to bind to (an outside connection)")
	portBase := fs.Int("port-base", 0, "connection i uses source port port-base+i (never one used moments before)")
	waitFor := fs.String("wait-file", "", "start once this file exists")
	presocket := fs.Bool("presocket", false, "create the socket before waiting for --wait-file (one connection)")
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	list, err := targets(*to)
	if err != nil {
		return nil, err
	}
	if *presocket {
		return presocketConnect(list[0], *waitFor, time.Duration(*timeout)*time.Millisecond)
	}
	var local netip.AddrPort
	if *localAddr != "" {
		addr, err := netip.ParseAddr(*localAddr)
		if err != nil {
			return nil, usageError{err}
		}
		local = netip.AddrPortFrom(addr, 0)
	}
	if *waitFor != "" {
		fmt.Printf("waiting pid:%d\n", os.Getpid())
	}
	if err := waitFile(*waitFor, 60*time.Second); err != nil {
		return nil, err
	}
	attempts := make([]Attempt, *count)
	var next atomic.Int64
	var wg sync.WaitGroup
	started := time.Now()
	for range max(1, min(*concurrency, *count)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if i >= *count {
					return
				}
				if *gap > 0 && i > 0 {
					time.Sleep(time.Duration(*gap) * time.Millisecond)
				}
				src := local
				if *portBase > 0 {
					addr := netip.IPv4Unspecified()
					if list[i%len(list)].Addr().Is6() {
						addr = netip.IPv6Unspecified()
					}
					if local.IsValid() {
						addr = local.Addr()
					}
					src = netip.AddrPortFrom(addr, uint16(*portBase+i))
				}
				attempts[i] = whoamiOnce(i, list[i%len(list)], src, *bindDev, time.Duration(*timeout)*time.Millisecond)
			}
		}()
	}
	wg.Wait()
	return summariseAttempts(attempts, time.Since(started), started.UnixMilli()), nil
}

// HoldResult is the tcphold mode's answer.
type HoldResult struct {
	Count       int            `json:"count"`
	Established int            `json:"established"`
	Errors      map[string]int `json:"errors"`
	Connect     Stats          `json:"connectMs"`
	FailedMS    Stats          `json:"failedMs"`
	StillOpen   int            `json:"stillOpen"` // established connections still open when the hold ended
	LocalPorts  []int          `json:"localPorts"`
	// With --window: the attempts refused (ECONNREFUSED or ECONNRESET) within
	// that many ms of starting, and the attempts with no outcome yet at that
	// point (in flight then, whatever happened later).
	WindowMS      int `json:"windowMs,omitempty"`
	RefusedWithin int `json:"refusedWithin"`
	PendingAt     int `json:"pendingAt"`
}

// Held is one held connection as the app sees it.
type Held struct {
	Local  string `json:"local"`
	Remote string `json:"remote"`
}

// HeldList is tcphold's "held {...}" line, with --tuples.
type HeldList struct {
	Established int    `json:"established"`
	Conns       []Held `json:"conns"`
}

// runTCPHold opens many connections and keeps them open (a connection storm,
// or many flows to list). Once every attempt is done it prints "holding <n>"
// (and with --tuples a "held {...}" line listing them), holds them for --hold
// ms or, with --release-file, until the case releases them, then reports.
func runTCPHold(args []string) (any, error) {
	fs := flag.NewFlagSet("tcphold", flag.ContinueOnError)
	to := fs.String("to", "", "servers ip:port[,...], used in turn")
	count := fs.Int("count", 100, "connections")
	concurrency := fs.Int("concurrency", 100, "attempts at once")
	timeout := fs.Int("timeout", 5000, "ms per attempt")
	hold := fs.Int("hold", 5000, "ms to keep them open (without --release-file)")
	release := fs.String("release-file", "", "keep them open until this file exists")
	tuples := fs.Bool("tuples", false, "print the held connections' addresses")
	window := fs.Int("window", 0, "classify attempts by what had happened this many ms after each started")
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	list, err := targets(*to)
	if err != nil {
		return nil, err
	}
	r := HoldResult{Count: *count, Errors: map[string]int{}, WindowMS: *window}
	var mu sync.Mutex
	var conns []net.Conn
	var connect, failed []float64
	var next atomic.Int64
	var wg sync.WaitGroup
	for range max(1, min(*concurrency, *count)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if i >= *count {
					return
				}
				start := time.Now()
				conn, err := net.DialTimeout("tcp", list[i%len(list)].String(), time.Duration(*timeout)*time.Millisecond)
				ms := msSince(start)
				code := Code(err)
				mu.Lock()
				if err != nil {
					r.Errors[code]++
					failed = append(failed, ms)
				} else {
					conns = append(conns, conn)
					connect = append(connect, ms)
				}
				if *window > 0 {
					switch {
					case ms >= float64(*window):
						r.PendingAt++
					case code == "ECONNREFUSED" || code == "ECONNRESET":
						r.RefusedWithin++
					}
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	r.Established = len(conns)
	r.Connect, r.FailedMS = Summarise(connect), Summarise(failed)
	fmt.Printf("holding %d\n", r.Established)
	if *tuples {
		list := HeldList{Established: len(conns), Conns: make([]Held, 0, len(conns))}
		for _, conn := range conns {
			list.Conns = append(list.Conns, Held{Local: addrString(conn.LocalAddr()), Remote: addrString(conn.RemoteAddr())})
		}
		line, err := json.Marshal(list)
		if err != nil {
			return nil, err
		}
		fmt.Printf("held %s\n", line)
	}
	if *release != "" {
		if err := waitFile(*release, ReleaseTimeout); err != nil {
			return nil, err
		}
	} else {
		time.Sleep(time.Duration(*hold) * time.Millisecond)
	}
	buf := make([]byte, 1)
	for _, conn := range conns {
		_ = conn.SetReadDeadline(time.Now().Add(time.Millisecond))
		if _, err := conn.Read(buf); Code(err) == "TIMEOUT" {
			r.StillOpen++
		}
		if ap, err := netip.ParseAddrPort(conn.LocalAddr().String()); err == nil {
			r.LocalPorts = append(r.LocalPorts, int(ap.Port()))
		}
		conn.Close()
	}
	return r, nil
}

// addrString is an address as "ip:port", with IPv4-mapped IPv6 unmapped.
func addrString(a net.Addr) string {
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String()
	}
	return a.String()
}

// ReuseResult is the reuse mode's answer.
type ReuseResult struct {
	LocalPort int       `json:"localPort"`
	Attempts  []Attempt `json:"attempts"`
	Gaps      []int     `json:"gapsMs"`
	Stalls    int       `json:"stalls"` // attempts over --stall ms, or failed
	MaxMS     float64   `json:"maxMs"`
	Stopped   bool      `json:"stoppedEarly"`
}

func runReuse(args []string) (any, error) {
	fs := flag.NewFlagSet("reuse", flag.ContinueOnError)
	to := fs.String("to", "", "whoami server ip:port")
	localPort := fs.Int("local-port", 0, "source port to use every time")
	gapList := fs.String("gaps", "1000", "ms to wait before each connection after the first, comma-separated; the last repeats")
	count := fs.Int("count", 4, "connections")
	timeout := fs.Int("timeout", 3000, "ms per connection")
	stall := fs.Float64("stall", 100, "a connection slower than this many ms is a stall")
	stopAfter := fs.Int("stop-after", 0, "stop after this many stalls (0: never)")
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	list, err := targets(*to)
	if err != nil {
		return nil, err
	}
	if *localPort <= 0 {
		return nil, usageError{fmt.Errorf("--local-port is required")}
	}
	var gaps []int
	for _, g := range strings.Split(*gapList, ",") {
		var ms int
		if _, err := fmt.Sscan(strings.TrimSpace(g), &ms); err != nil {
			return nil, usageError{fmt.Errorf("bad gap %q", g)}
		}
		gaps = append(gaps, ms)
	}
	local := netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(*localPort))
	if list[0].Addr().Is6() {
		local = netip.AddrPortFrom(netip.IPv6Unspecified(), uint16(*localPort))
	}
	r := ReuseResult{LocalPort: *localPort}
	for i := range *count {
		gap := 0
		if i > 0 {
			gap = gaps[min(i-1, len(gaps)-1)]
			time.Sleep(time.Duration(gap) * time.Millisecond)
		}
		// The app's own kernel refuses the port until its last socket on it has
		// finished closing (LAST_ACK, which waits for the engine's final ACK).
		// That wait is part of the reuse, so it counts toward a stall.
		began := time.Now()
		var a Attempt
		for {
			a = whoamiOnce(i, list[0], local, "", time.Duration(*timeout)*time.Millisecond)
			if (a.Err != "EADDRNOTAVAIL" && a.Err != "EADDRINUSE") || time.Since(began) > time.Duration(*stall*float64(time.Millisecond)) {
				break
			}
			a.Retries++
			time.Sleep(time.Millisecond)
		}
		a.TotalMS = msSince(began)
		r.Attempts = append(r.Attempts, a)
		r.Gaps = append(r.Gaps, gap)
		r.MaxMS = max(r.MaxMS, a.TotalMS)
		if a.Err != "" || a.TotalMS > *stall {
			r.Stalls++
			if *stopAfter > 0 && r.Stalls >= *stopAfter {
				r.Stopped = i+1 < *count
				break
			}
		}
	}
	return r, nil
}

// StreamResult is the stream mode's answer. Times are Unix ms.
type StreamResult struct {
	Connected   bool           `json:"connected"`
	ConnectErr  string         `json:"connectErr,omitempty"`
	ConnectedAt int64          `json:"connectedAt,omitempty"`
	LocalAddr   string         `json:"localAddr,omitempty"`
	Pings       int            `json:"pings"`
	Pongs       int            `json:"pongs"`
	Seen        map[string]int `json:"seen"`
	LastPongAt  int64          `json:"lastPongAt,omitempty"`
	MaxGapMS    int64          `json:"maxGapMs"`
	ClosedAt    int64          `json:"closedAt,omitempty"`
	CloseErr    string         `json:"closeErr,omitempty"`
	EndedAt     int64          `json:"endedAt"`
}

func runStream(args []string) (any, error) {
	fs := flag.NewFlagSet("stream", flag.ContinueOnError)
	to := fs.String("to", "", "stream server ip:port")
	duration := fs.Int("duration", 10000, "ms to keep the connection")
	interval := fs.Int("interval", 200, "ms between pings")
	localAddr := fs.String("local-addr", "", "source address to bind")
	bindDev := fs.String("bind-dev", "", "interface to bind to (an outside connection)")
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	list, err := targets(*to)
	if err != nil {
		return nil, err
	}
	r := StreamResult{Seen: map[string]int{}}
	d := net.Dialer{Timeout: 5 * time.Second, Control: socketOptions(*bindDev)}
	if *localAddr != "" {
		addr, err := netip.ParseAddr(*localAddr)
		if err != nil {
			return nil, usageError{err}
		}
		d.LocalAddr = net.TCPAddrFromAddrPort(netip.AddrPortFrom(addr, 0))
	}
	end := time.Now().Add(time.Duration(*duration) * time.Millisecond)
	conn, err := d.Dial("tcp", list[0].String())
	if err != nil {
		r.ConnectErr = Code(err)
		r.EndedAt = nowMS()
		return r, nil
	}
	defer conn.Close()
	r.Connected, r.ConnectedAt, r.LocalAddr = true, nowMS(), conn.LocalAddr().String()
	var mu sync.Mutex
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		scanner := bufio.NewScanner(conn)
		last := r.ConnectedAt
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			now := nowMS()
			mu.Lock()
			r.Pongs++
			if len(fields) == 3 {
				r.Seen[fields[2]]++
			}
			r.MaxGapMS = max(r.MaxGapMS, now-last)
			r.LastPongAt, last = now, now
			mu.Unlock()
		}
		mu.Lock()
		r.ClosedAt, r.CloseErr = nowMS(), Code(scanner.Err())
		if r.CloseErr == "" {
			r.CloseErr = "EOF"
		}
		mu.Unlock()
	}()
	ticker := time.NewTicker(time.Duration(*interval) * time.Millisecond)
	defer ticker.Stop()
loop:
	for time.Now().Before(end) {
		select {
		case <-closed:
			break loop
		case <-ticker.C:
			mu.Lock()
			r.Pings++
			n := r.Pings
			mu.Unlock()
			_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if _, err := fmt.Fprintf(conn, "ping %d\n", n); err != nil {
				break loop
			}
		}
	}
	// Ending on our side isn't a close the case cares about.
	mu.Lock()
	ended := r.ClosedAt != 0
	mu.Unlock()
	_ = conn.Close()
	<-closed
	mu.Lock()
	defer mu.Unlock()
	if !ended {
		r.ClosedAt, r.CloseErr = 0, ""
	}
	r.MaxGapMS = max(r.MaxGapMS, min(nowMS(), end.UnixMilli())-max(r.LastPongAt, r.ConnectedAt))
	r.EndedAt = nowMS()
	return r, nil
}

// HTTPResult is the http mode's answer.
type HTTPResult struct {
	Status int     `json:"status"`
	Seen   string  `json:"seen,omitempty"`
	Err    string  `json:"err,omitempty"`
	MS     float64 `json:"ms"`
}

func runHTTP(args []string) (any, error) {
	fs := flag.NewFlagSet("http", flag.ContinueOnError)
	url := fs.String("url", "", "http://ip:port/path")
	timeout := fs.Int("timeout", 5000, "ms")
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout:   time.Duration(*timeout) * time.Millisecond,
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
	}
	r := HTTPResult{}
	start := time.Now()
	resp, err := client.Get(*url)
	if err != nil {
		r.Err, r.MS = Code(err), msSince(start)
		return r, nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	r.Status, r.Seen, r.MS = resp.StatusCode, strings.TrimSpace(string(body)), msSince(start)
	if err != nil {
		r.Err = Code(err)
	}
	return r, nil
}

// BulkResult is the bulk mode's answer.
type BulkResult struct {
	Bytes  int64   `json:"bytes"`
	OK     bool    `json:"ok"`
	Err    string  `json:"err,omitempty"`
	MS     float64 `json:"ms"`
	Upload bool    `json:"upload"`
}

func runBulk(args []string) (any, error) {
	fs := flag.NewFlagSet("bulk", flag.ContinueOnError)
	to := fs.String("to", "", "bulk server ip:port")
	size := fs.Int64("bytes", 1<<20, "bytes to move")
	upload := fs.Bool("upload", false, "upload instead of download")
	timeout := fs.Int("timeout", 60000, "ms for the whole transfer")
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	list, err := targets(*to)
	if err != nil {
		return nil, err
	}
	r := BulkResult{Upload: *upload}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", list[0].String(), 10*time.Second)
	if err != nil {
		r.Err = Code(err)
		return r, nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(start.Add(time.Duration(*timeout) * time.Millisecond))
	want := wire.PatternSHA256(*size)
	if *upload {
		if _, err := fmt.Fprintf(conn, "PUT %d\n", *size); err == nil {
			_, err = io.Copy(conn, wire.Pattern(*size))
			r.Bytes = *size
			if err != nil {
				r.Err = Code(err)
			}
		}
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil && r.Err == "" {
			r.Err = Code(err)
		}
		r.OK = r.Err == "" && strings.TrimSpace(line) == want
		if r.Err == "" && !r.OK {
			r.Err = "server hash " + strings.TrimSpace(line)
		}
	} else {
		if _, err := fmt.Fprintf(conn, "GET %d\n", *size); err != nil {
			r.Err = Code(err)
			return r, nil
		}
		h := sha256.New()
		n, err := io.Copy(h, conn)
		r.Bytes = n
		if err != nil {
			r.Err = Code(err)
		}
		r.OK = n == *size && hex.EncodeToString(h.Sum(nil)) == want
		if r.Err == "" && !r.OK {
			r.Err = fmt.Sprintf("got %d of %d bytes or a different hash", n, *size)
		}
	}
	r.MS = msSince(start)
	return r, nil
}
