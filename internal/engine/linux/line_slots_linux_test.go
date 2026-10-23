package linux

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

func TestLineSlotChurnKeepsLiveSocketAndReusesRetiredSlots(t *testing.T) {
	p := &Platform{lines: map[string]lineState{}}
	held := &lineLease{}
	held.hold()
	p.lines["held"] = lineState{N: 1, lease: held}
	policyLine := "held"
	p.SetLineUse(func(id string) bool { return id == policyLine })
	for i := 0; i < 1024; i++ {
		id := fmt.Sprint(i)
		p.retireLines(map[string]bool{id: true})
		n := p.freeLineSlot(p.lines, time.Now())
		if n == 0 || n == 1 || len(p.lines) > 2 {
			t.Fatal("slot leaked or live slot reused", i, n, len(p.lines))
		}
		p.lines[id] = lineState{N: n, lease: &lineLease{}}
		policyLine = id
		p.retireLines(map[string]bool{id: true})
		if p.lines["held"].N != 1 {
			t.Fatal("held binding changed")
		}
	}
	held.release()
	p.retireLines(map[string]bool{policyLine: true})
	if _, ok := p.lines["held"]; ok || held.hold() || p.slotQuiet[1].IsZero() || !p.slotsDirty {
		t.Fatal("retired slot still acquirable or not reusable")
	}
}

func TestLineSlotQuietPeriodAndRotation(t *testing.T) {
	now := time.Now()
	lease := &lineLease{}
	lease.hold()
	lease.release()
	closed := *lease.closedAt.Load()
	p := &Platform{lines: map[string]lineState{"closed": {N: 1, lease: lease}}}
	p.retireLines(nil)
	for i := 2; i <= 255; i++ {
		if n := p.freeLineSlot(p.lines, now); n != i {
			t.Fatal("did not rotate to unused slot", n, i)
		}
		p.lines[fmt.Sprint(i)] = lineState{N: i}
	}
	if n := p.freeLineSlot(p.lines, closed.Add(lineSlotQuiet-time.Nanosecond)); n != 0 {
		t.Fatal("closed socket slot reused early", n)
	}
	if n := p.freeLineSlot(p.lines, closed.Add(lineSlotQuiet)); n != 1 {
		t.Fatal("quiet slot did not become reusable", n)
	}
}

func TestLineSlotRetirementRacesAnOldPublishedBinding(t *testing.T) {
	for range 1000 {
		l := &lineLease{}
		var held, retired bool
		var wg sync.WaitGroup
		wg.Go(func() { held = l.hold() })
		wg.Go(func() { retired = l.retire() })
		wg.Wait()
		if held && retired {
			t.Fatal("retired slot acquired a socket")
		}
		if held {
			l.release()
			if !l.retire() {
				t.Fatal("reference leaked")
			}
		}
		if l.hold() {
			t.Fatal("stale snapshot resurrected a slot")
		}
	}
}

func TestProbeUnavailableClassifiesOnlyLocalResources(t *testing.T) {
	for _, err := range []error{syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM, syscall.EADDRINUSE} {
		if !probeUnavailable(fmt.Errorf("socket: %w", err)) {
			t.Fatal(err)
		}
	}
	if probeUnavailable(syscall.ECONNREFUSED) || probeUnavailable(context.DeadlineExceeded) || probeUnavailable(syscall.EADDRNOTAVAIL) {
		t.Fatal("line failure treated as engine overload")
	}
	for _, quick := range []bool{true, false} {
		for _, tc := range []struct {
			name      string
			addresses []netip.Addr
			route     bool
			outcome   string
		}{
			{"ephemeral-ports", []netip.Addr{netip.MustParseAddr("2001:db8::2")}, true, "engineUnavailable"},
			{"missing-source", nil, true, "lineFailed"},
			{"wrong-family", []netip.Addr{netip.MustParseAddr("192.0.2.1")}, true, "lineFailed"},
			{"link-local-only", []netip.Addr{netip.MustParseAddr("fe80::1")}, true, "lineFailed"},
			{"missing-route", []netip.Addr{netip.MustParseAddr("2001:db8::2")}, false, "lineFailed"},
		} {
			p := &Platform{ProbeError: func() error { return fmt.Errorf("connect: %w", syscall.EADDRNOTAVAIL) }}
			p.bindings.Store(&bindingSnapshot{capturing: true, lines: map[string]lineState{"line": {Up: true, Default6: tc.route, Addresses: tc.addresses}}})
			r, err := p.ProbeConfigured(context.Background(), "line", platform.ProbeRequest{Target: "[2001:db8::1]:443", Custom: true, Quick: quick})
			if err != nil || r.Outcome != tc.outcome {
				t.Fatal(tc.name, quick, r, err)
			}
		}
	}
}
