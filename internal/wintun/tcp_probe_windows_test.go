//go:build windows

package wintun

import (
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
)

type tcpProgressConn struct {
	net.Conn
	read, written atomic.Uint64
}

func (c *tcpProgressConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read.Add(uint64(n))
	return n, err
}

func (c *tcpProgressConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.written.Add(uint64(n))
	return n, err
}

type tcpProbe struct {
	t       *testing.T
	f       *fixture
	link    *ns.Link
	stack   *gv.Stack
	done    chan struct{}
	joined  chan struct{}
	start   time.Time
	trace   atomic.Bool
	mu      sync.Mutex
	packets map[string][]string
}

func startTCPProbe(t *testing.T, f *fixture, link *ns.Link, stack *gv.Stack) *tcpProbe {
	p := &tcpProbe{t: t, f: f, link: link, stack: stack, done: make(chan struct{}), joined: make(chan struct{}), start: time.Now(), packets: make(map[string][]string)}
	go func() {
		defer close(p.joined)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-p.done:
				return
			case <-ticker.C:
				if time.Since(p.start) >= 3*time.Second {
					p.trace.Store(true)
					p.snapshot("running")
				}
			}
		}
	}()
	return p
}

func (p *tcpProbe) stop() {
	close(p.done)
	<-p.joined
	p.snapshot("before_teardown")
}

func (p *tcpProbe) snapshot(reason string) {
	s, _ := p.f.io.(*Session)
	p.mu.Lock()
	defer p.mu.Unlock()
	report(p.t, map[string]any{"test": "tcp_probe", "reason": reason, "seconds": time.Since(p.start).Seconds(), "state": observeSession(s), "link_drops": p.link.Dropped.Load(), "tcp_stats": p.stack.Stats().TCP, "packets": p.packets, "fault": fmt.Sprint(p.f.fault())})
}

func (p *tcpProbe) packet(direction string, b []byte) {
	if !p.trace.Load() || len(b) < 40 || b[0]>>4 != 4 || b[9] != 6 {
		return
	}
	ip := int(b[0]&15) * 4
	if ip < 20 || len(b) < ip+20 {
		return
	}
	tcp := b[ip:]
	key := fmt.Sprintf("%s:%d:%d", direction, binary.BigEndian.Uint16(tcp), binary.BigEndian.Uint16(tcp[2:]))
	sample := fmt.Sprintf("%.3fs seq=%d ack=%d flags=%02x win=%d data=%d", time.Since(p.start).Seconds(), binary.BigEndian.Uint32(tcp[4:]), binary.BigEndian.Uint32(tcp[8:]), tcp[13], binary.BigEndian.Uint16(tcp[14:]), len(tcp)-int(tcp[12]>>4)*4)
	p.mu.Lock()
	history := append(p.packets[key], sample)
	if len(history) > 8 {
		history = history[len(history)-8:]
	}
	p.packets[key] = history
	p.mu.Unlock()
}

func TestWintunTCPProbe(t *testing.T) {
	requireRunner(t)
	for trial := 0; trial < 20; trial++ {
		for _, mode := range []string{"ours", "dll"} {
			t.Run(fmt.Sprintf("trial%d/%s", trial, mode), func(t *testing.T) {
				f := newFixture(t, mode, 0)
				f.stopEcho()
				f.stopEcho = func() {}
				stop := tcpEcho(t, f)
				defer stop()
				for warm := 0; warm < 2; warm++ {
					_, err := tcpTransfer(t, 1)
					must(t, err)
				}
				rate, err := tcpTransfer(t, 8)
				if err != nil {
					s, _ := f.io.(*Session)
					report(t, map[string]any{"test": "tcp_failure_before_teardown", "mode": mode, "trial": trial, "streams": 8, "state": observeSession(s), "error": err.Error(), "fault": fmt.Sprint(f.fault())})
					stack := make([]byte, 1<<20)
					t.Logf("TCP failure goroutines:\n%s", stack[:runtime.Stack(stack, true)])
					t.Fatal(err)
				}
				report(t, map[string]any{"test": "tcp8_probe_success", "mode": mode, "trial": trial, "MBps": rate})
			})
		}
	}
}
