package linux

import (
	"context"
	"fmt"
	"sync"
	"syscall"
	"testing"
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
		n := freeLineSlot(p.lines)
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
	if _, ok := p.lines["held"]; ok || held.hold() || freeLineSlot(p.lines) != 1 || !p.slotsDirty {
		t.Fatal("retired slot still acquirable or not reusable")
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
	for _, err := range []error{syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM, syscall.EADDRINUSE, syscall.EADDRNOTAVAIL} {
		if !probeUnavailable(fmt.Errorf("socket: %w", err)) {
			t.Fatal(err)
		}
	}
	if probeUnavailable(syscall.ECONNREFUSED) || probeUnavailable(context.DeadlineExceeded) {
		t.Fatal("line failure treated as engine overload")
	}
}
