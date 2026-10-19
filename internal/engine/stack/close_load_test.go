package stack_test

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestCloseAtCapUnderLoad(t *testing.T) {
	if os.Getenv("NETSWITCH_TIMEWAIT_GATE") != "1" {
		t.Skip("sustained load runs in CI")
	}
	clock := faketime.NewManualClock()
	o := ns.DefaultOptions()
	o.Clock = clock
	limits := flows.Defaults()
	limits.Flows, limits.PerApp = 1, 1
	limits.TimeWait = 0
	p := newPeerOptions(t, false, limits, o)
	paths := []string{"app_fin", "remote_fin", "simultaneous", "app_rst", "remote_rst", "policy", "idle"}
	counts := make(map[string]int)
	start := time.Now()
	n := 0
	for time.Since(start) < 3*time.Second || n < 700 {
		p.port = uint16(20000 + n%40000)
		p.open(1000 + uint32(n))
		p.upload([]byte("load"))
		path := paths[n%len(paths)]
		p.phase = "at-cap load: " + path
		if g := p.table.Stats(); g.Flows != 1 {
			t.Fatal("app not at its cap", p.diagnostics())
		}
		switch path {
		case "app_fin", "simultaneous":
			last := p.prepareFinalACK(path == "simultaneous")
			p.inject(last)
		case "remote_fin":
			p.closeActive()
		case "app_rst":
			p.inject(p.packet(p.seq, p.ack, header.TCPFlagRst|header.TCPFlagAck, nil))
		case "remote_rst", "policy":
			if path == "remote_rst" {
				p.current.conn.Abort(errors.New("remote reset"))
			} else {
				if result, err := p.table.CloseFlows(flows.Selector{Line: "B"}, 0); err != nil || result.Closed != 1 {
					t.Fatal(result, err)
				}
			}
			for {
				h := p.read(time.Second)
				if h == nil {
					t.Fatal("missing close reset", p.diagnostics())
				}
				if h.DestinationPort() == p.port && h.Flags().Contains(header.TCPFlagRst) {
					break
				}
			}
		case "idle":
			ep := p.endpoint()
			idle, interval := tcpip.KeepaliveIdleOption(time.Second), tcpip.KeepaliveIntervalOption(time.Second)
			if err := ep.SetSockOpt(&idle); err != nil {
				t.Fatal(err)
			}
			if err := ep.SetSockOpt(&interval); err != nil {
				t.Fatal(err)
			}
			if err := ep.SetSockOptInt(tcpip.KeepaliveCountOption, 1); err != nil {
				t.Fatal(err)
			}
			clock.Advance(2 * time.Second)
		}
		p.current.conn.Close()
		counts[path]++
		n++
		if g := p.table.Stats(); g.Rejected != 0 || p.forward.Rejected.Load() != 0 {
			t.Fatal("false budget reset", p.diagnostics())
		}
	}
	// Exercise admission after the final close too. A timer-driven close is
	// reclaimed by the next admission, so stopping on idle must not mistake
	// a deferred reservation for a rejection, or leave that last reuse untested.
	p.port++
	p.open(1000 + uint32(n))
	p.upload([]byte("load"))
	p.inject(p.packet(p.seq, p.ack, header.TCPFlagRst|header.TCPFlagAck, nil))
	p.current.conn.Close()
	counts["app_rst"]++
	n++
	if g := p.table.Stats(); g.Admitted != uint64(n) || g.Flows != 0 || g.TimeWait != 0 || p.dials.Load() != uint64(n) {
		t.Fatal(p.diagnostics())
	}
	// Upstream relay accounting may finish just after the close packet. Drain
	// all relays before checking exact bytes; the load itself never waits.
	p.forward.Stop()
	p.stack.Close()
	p.stack.Wait()
	p.forward.Wait()
	if got := p.table.Totals().Apps["peer"].Up; got != uint64(n*4) {
		t.Fatalf("upload accounting=%d want=%d", got, n*4)
	}
	t.Logf("%d connections in %s at flow/per-app cap=1; each path=%v; false budget RST=0; payloads hash-checked", n, time.Since(start), counts)
}
