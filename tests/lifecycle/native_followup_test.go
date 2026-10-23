package lifecycle_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/testproxy"
)

type nativeProbeFixture struct {
	target string
	wrong  func(*testing.T, bool)
	seen   func(*testing.T) (int, string)
}

func nativeFollowup(t *testing.T, c *nativeClient, f tunFixture, p nativeProbeFixture, faults bool, rev *policy.Revision, held net.Conn) {
	t.Run("custom-quick-and-HTTPS-probes", func(t *testing.T) {
		before, _ := p.seen(t)
		var result platform.ProbeResult
		probe := func(op string, quick bool) {
			nativeMust(t, c, "probe", map[string]any{"opId": op, "line": "a1", "target": p.target, "quick": quick, "custom": true}, &result)
		}
		probe("quick-custom", true)
		if !result.OK || result.Outcome != "ok" {
			t.Fatal("bound quick probe", result)
		}
		probe("full-custom", false)
		count, last := p.seen(t)
		if faults {
			if !result.OK || result.Outcome != "ok" || count != before+1 || last != "HEAD /" {
				t.Fatal("full custom did not send exactly one verified HTTPS HEAD", result, count, last)
			}
			p.wrong(t, true)
			probe("bad-certificate", false)
			p.wrong(t, false)
			if result.OK || result.Outcome != "lineFailed" {
				t.Fatal("wrong IP certificate accepted", result)
			}
			for _, quick := range []bool{true, false} {
				nativeMust(t, c, "testFault", map[string]any{"fault": map[string]any{"kind": "probe-exhaustion"}}, nil)
				probe("resource-"+strconv.FormatBool(quick), quick)
				if result.OK || result.Outcome != "engineUnavailable" {
					t.Fatal("local exhaustion counted against line", result)
				}
				nativeEcho(t, held, "held-through-probe-exhaustion")
			}
		} else if result.OK || result.Outcome != "lineFailed" || count != before {
			t.Fatal("product trusted test CA or skipped certificate validation", result, count)
		}
		t.Logf("NATIVE_CUSTOM_PROBE faults=%t observed_requests=%d method_path=%q", faults, count-before, last)
	})
	t.Run("unacked-totals-do-not-starve-flows", func(t *testing.T) {
		var receipts []string
		for range 4 {
			var page flows.TotalsPage
			nativeMust(t, c, "totals", nil, &page)
			if page.Cursor != "" {
				t.Fatal("small accounting fixture unexpectedly paged")
			}
			receipts = append(receipts, page.Receipt)
		}
		var page flows.Page
		nativeMust(t, c, "flows", nil, &page)
		if len(page.Flows) == 0 {
			t.Fatal("live flow listing disappeared")
		}
		nativeEcho(t, held, "held-through-unacked-totals")
		for i, receipt := range receipts {
			nativeMust(t, c, "ackTotals", map[string]any{"opId": fmt.Sprint("unacked-", i), "receipt": receipt}, nil)
		}
	})
	t.Run("test-proxy-product-boundary", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		var status testproxy.Status
		if err := c.call(ctx, "testProxy", map[string]any{"opId": "wildcard-proxy", "listen": "0.0.0.0:0"}, &status); err == nil {
			t.Fatal("wildcard test proxy accepted")
		}
		if !faults {
			l, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := l.Addr().String()
			l.Close()
			if err := c.call(ctx, "testProxy", map[string]any{"opId": "product-proxy", "listen": address}, &status); err == nil || !strings.Contains(err.Error(), "disabled") {
				t.Fatal("product test proxy not disabled", err)
			}
			if conn, err := f.dial(ctx, "tcp4", address); err == nil {
				conn.Close()
				t.Fatal("product opened test-proxy listener")
			}
			return
		}
		nativeMust(t, c, "testProxy", map[string]any{"opId": "proxy-start", "listen": "127.0.0.1:0"}, &status)
		address, err := netip.ParseAddrPort(status.Address)
		if err != nil || !address.Addr().IsLoopback() {
			t.Fatal(status, err)
		}
		for _, socks := range []bool{false, true} {
			conn, err := f.dial(ctx, "tcp4", status.Address)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { conn.Close() })
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			if socks {
				dst := netip.MustParseAddrPort(f.target)
				b := append([]byte{5, 1, 0, 5, 1, 0, 1}, dst.Addr().AsSlice()...)
				b = append(b, byte(dst.Port()>>8), byte(dst.Port()))
				if _, err = conn.Write(b); err != nil {
					t.Fatal(err)
				}
				var reply [12]byte
				if _, err = io.ReadFull(conn, reply[:]); err != nil || reply[1] != 0 || reply[3] != 0 {
					t.Fatal(reply, err)
				}
			} else {
				if _, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", f.target, f.target); err != nil {
					t.Fatal(err)
				}
				r := bufio.NewReader(conn)
				line, err := r.ReadString('\n')
				if err != nil || !strings.Contains(line, "200") {
					t.Fatal(line, err)
				}
				if _, err = r.ReadString('\n'); err != nil {
					t.Fatal(err)
				}
			}
			nativeEcho(t, conn, fmt.Sprint("native-proxy-", socks))
			var listed flows.Page
			nativeMust(t, c, "flows", nil, &listed)
			found := false
			for _, flow := range listed.Flows {
				found = found || flow.Source.Addr().IsLoopback() && flow.Destination == netip.MustParseAddrPort(f.target) && flow.Line == "a1"
			}
			conn.Close()
			if !found {
				t.Fatal("proxy bypassed shared flow table/policy", listed)
			}
		}
		// An IPv4 proxy transport must not bypass the routed IPv6 policy.
		v6, err := f.dial(ctx, "tcp4", status.Address)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { v6.Close() })
		v6.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := fmt.Fprint(v6, "CONNECT [2001:db8::1]:443 HTTP/1.1\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		denied, err := bufio.NewReader(v6).ReadString('\n')
		v6.Close()
		if err != nil || !strings.Contains(denied, "403") {
			t.Fatal("proxy bypassed IPv6 policy", denied, err)
		}
		serial := 0
		observe := func() testproxy.Status {
			serial++
			var current testproxy.Status
			nativeMust(t, c, "testProxy", map[string]any{"opId": fmt.Sprint("proxy-observe-", serial), "listen": status.Address}, &current)
			return current
		}
		wait(t, "completed proxy flows release sessions", 2*time.Second, func() bool { return observe().Connections == 0 })
		pending := make([]net.Conn, 0, 64)
		for range 64 {
			conn, err := f.dial(ctx, "tcp4", status.Address)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { conn.Close() })
			pending = append(pending, conn)
		}
		wait(t, "64 independently held proxy clients", time.Second, func() bool { return observe().Connections == len(pending) })
		extra, err := f.dial(ctx, "tcp4", status.Address)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { extra.Close() })
		extra.SetReadDeadline(time.Now().Add(time.Second))
		var byteRead [1]byte
		n, refusal := extra.Read(byteRead[:])
		extra.Close()
		if timeout, ok := refusal.(net.Error); n != 0 || refusal == nil || (ok && timeout.Timeout()) {
			t.Fatal("proxy overflow not refused promptly", n, refusal)
		}
		nativeEcho(t, held, "TUN-and-control-work-during-proxy-exhaustion")
		if current := observe(); current.Connections != len(pending) {
			t.Fatal("proxy exhaustion precondition ended before protected traffic completed", current)
		}
		for _, conn := range pending {
			conn.Close()
		}
		wait(t, "proxy capacity recovers", 2*time.Second, func() bool { return observe().Connections == 0 })
		fresh, err := f.dial(ctx, "tcp4", status.Address)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { fresh.Close() })
		fresh.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := fmt.Fprintf(fresh, "CONNECT %s HTTP/1.1\r\n\r\n", f.target); err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(fresh)
		line, err := reader.ReadString('\n')
		if err != nil || !strings.Contains(line, "200") {
			t.Fatal(line, err)
		}
		if _, err := reader.ReadString('\n'); err != nil {
			t.Fatal(err)
		}
		nativeEcho(t, fresh, "proxy-fresh-after-capacity")
		fresh.Close()
		nativeEcho(t, held, "TUN-independent-of-test-proxy")
	})
	if !faults {
		t.Run("cold-missing-line-and-slot-churn", func(t *testing.T) {
			base := rev.Config
			start := time.Now()
			line, seen := f.line, f.seen
			if f.churnLine != "" {
				line, seen = f.churnLine, f.churnSeen
			}
			check := func(conn net.Conn, marker, source string) {
				reply := nativeEcho(t, conn, marker)
				if source != "" && !strings.HasSuffix(strings.TrimSpace(reply), " "+source) {
					t.Fatal("physical line changed", reply, source)
				}
			}
			for i := 0; i < 300; i++ {
				config := policy.Config{Lines: []platform.Line{{ID: fmt.Sprint("churn-", i), Interface: line}}}
				rev.N++
				rev.Config = config
				rev.Hash = policy.Hash(config)
				nativeMust(t, c, "apply", map[string]any{"revision": *rev}, nil)
				if i%25 == 0 {
					check(held, "held-line-retired-from-policy", f.seen)
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					fresh, err := f.dial(ctx, "tcp4", f.target)
					cancel()
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { fresh.Close() })
					check(fresh, "new-flow-on-reused-slot", seen)
					fresh.Close()
				}
			}
			if runtime.GOOS == "linux" {
				wait(t, "closed socket slots retire", 5*time.Second, func() bool {
					var stats struct {
						Engine struct {
							Dialer struct{ LineSlots, ConfiguredLines int }
						}
					}
					nativeMust(t, c, "stats", nil, &stats)
					d := stats.Engine.Dialer
					// Require the actual nested counters: a missing field must not
					// pass as a zero-sized retained set.
					return d.ConfiguredLines == 1 && d.LineSlots >= 2 && d.LineSlots <= 3
				})
			}
			rev.N++
			rev.Config = base
			rev.Hash = policy.Hash(base)
			nativeMust(t, c, "apply", map[string]any{"revision": *rev}, nil)
			nativeEcho(t, held, "held-after-300-line-identities")
			t.Logf("NATIVE_LINE_CHURN revisions=300 instance=%s elapsed=%s held_flow_preserved=true", c.instance, time.Since(start))
		})
	}
}
