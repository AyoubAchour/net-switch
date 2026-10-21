//go:build linux

package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/wire"
)

// SweepRequest is what a case writes to udpflood's --sweep-file once the
// flood's sessions are held: the sockets, by index, whose sessions the case
// saw held, and how to sweep them.
type SweepRequest struct {
	Sockets       []int `json:"sockets"`
	Concurrency   int   `json:"concurrency"`
	EchoTimeoutMS int   `json:"echoTimeoutMs"`
	// BudgetMS stops starting new echoes after this long; the sockets not
	// tried are reported, never silently dropped.
	BudgetMS int `json:"budgetMs"`
}

// SweepResult is the sweep's answer, printed as "sweep {json}". Each slice
// lines up with Sockets.
type SweepResult struct {
	Token   string `json:"token"`
	Sockets []int  `json:"sockets"`
	// RTTMicros is each echo's round trip, from just before the send to its
	// own answer; -1 when no matching answer came (or it was never sent).
	RTTMicros []int64 `json:"rttUs"`
	// Seen is the source the server saw, from the echo's answer.
	Seen        []string       `json:"seen"`
	Errors      map[string]int `json:"errors"`
	Unsent      int            `json:"unsent"`
	Stale       int            `json:"stale"` // earlier datagrams read and set aside before an echo's own answer
	MaxInFlight int            `json:"maxInFlight"`
	DurationUS  int64          `json:"durationUs"`
}

// sweepThenHold prints the flood's result, then waits for the case: a sweep
// request runs one echo through each listed socket's held session before the
// sockets are held again until release; release alone lets them go.
func sweepThenHold(conns []net.Conn, tok, sweepFile, release string, r FloodResult) (any, error) {
	if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
		return nil, err
	}
	first, err := waitEither(sweepFile, release, ReleaseTimeout)
	if err != nil || first == release {
		return nil, err
	}
	data, err := os.ReadFile(sweepFile)
	if err != nil {
		return nil, err
	}
	var req SweepRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("sweep request: %w", err)
	}
	if req.Concurrency <= 0 || req.EchoTimeoutMS <= 0 || req.BudgetMS <= 0 {
		return nil, fmt.Errorf("sweep request needs concurrency, echo timeout and budget: %+v", req)
	}
	for _, i := range req.Sockets {
		if i < 0 || i >= len(conns) {
			return nil, fmt.Errorf("sweep socket %d is not one of the %d opened", i, len(conns))
		}
	}
	out, err := json.Marshal(sweep(conns, tok, req))
	if err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintf(os.Stdout, "sweep %s\n", out); err != nil {
		return nil, err
	}
	return nil, waitFile(release, ReleaseTimeout)
}

// sweep sends one echo through each requested socket, at most
// req.Concurrency at a time, and times each round trip. An echo is sent
// once: a missing answer is reported, never retried.
func sweep(conns []net.Conn, tok string, req SweepRequest) SweepResult {
	n := len(req.Sockets)
	res := SweepResult{Token: tok, Sockets: req.Sockets, RTTMicros: make([]int64, n), Seen: make([]string, n), Errors: map[string]int{}}
	for k := range res.RTTMicros {
		res.RTTMicros[k] = -1
	}
	timeout := time.Duration(req.EchoTimeoutMS) * time.Millisecond
	var mu sync.Mutex
	inFlight := 0
	next := make(chan int)
	var wg sync.WaitGroup
	start := time.Now()
	budget := start.Add(time.Duration(req.BudgetMS) * time.Millisecond)
	for range req.Concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 2048)
			for k := range next {
				i := req.Sockets[k]
				c := conns[i]
				want := payload(tok, 1, i, 0)
				mu.Lock()
				if time.Now().After(budget) {
					res.Unsent++
					mu.Unlock()
					continue
				}
				inFlight++
				res.MaxInFlight = max(res.MaxInFlight, inFlight)
				mu.Unlock()
				sent := time.Now()
				_ = c.SetReadDeadline(sent.Add(timeout))
				var seen netip.AddrPort
				stale := 0
				_, err := c.Write(want)
				for err == nil {
					var got int
					if got, err = c.Read(buf); err != nil {
						break
					}
					src, echoed, perr := wire.ParseEchoReply(buf[:got])
					if perr == nil && bytes.Equal(echoed, want) {
						seen = src
						break
					}
					stale++
				}
				rtt := time.Since(sent)
				mu.Lock()
				inFlight--
				res.Stale += stale
				if err != nil {
					res.Errors[Code(err)]++
				} else {
					res.RTTMicros[k] = rtt.Microseconds()
					res.Seen[k] = seen.String()
				}
				mu.Unlock()
			}
		}()
	}
	for k := range n {
		next <- k
	}
	close(next)
	wg.Wait()
	res.DurationUS = time.Since(start).Microseconds()
	return res
}

// waitEither blocks until a or b exists and says which appeared first.
func waitEither(a, b string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for {
		for _, path := range []string{a, b} {
			if path == "" {
				continue
			}
			if _, err := os.Stat(path); err == nil {
				return path, nil
			} else if !errors.Is(err, os.ErrNotExist) {
				return "", err
			}
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("neither %s nor %s appeared within %s", a, b, timeout)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
