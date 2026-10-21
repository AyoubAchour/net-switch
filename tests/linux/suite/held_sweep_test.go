//go:build linux

package suite

import (
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/app"
	"github.com/AyoubAchour/net-switch/tests/linux/engine"
)

// sweepOf builds an app's sweep result: every socket answered from its held
// source in fast, apart from the overrides (-1 for no answer).
func sweepOf(held map[int]string, sockets []int, fast time.Duration, rtt map[int]time.Duration, seen map[int]string) app.SweepResult {
	res := app.SweepResult{Token: "t", Sockets: sockets, MaxInFlight: sweepConcurrency}
	for _, i := range sockets {
		d, ok := rtt[i]
		if !ok {
			d = fast
		}
		src, ok := seen[i]
		if !ok {
			src = held[i]
		}
		if d < 0 {
			res.RTTMicros = append(res.RTTMicros, -1)
			res.Seen = append(res.Seen, "")
			continue
		}
		res.RTTMicros = append(res.RTTMicros, d.Microseconds())
		res.Seen = append(res.Seen, src)
	}
	return res
}

func heldOf(n int) (map[int]string, []int) {
	held := map[int]string{}
	var sockets []int
	for i := range n {
		held[i] = "192.0.2.1:" + string(rune('0'+i%10))
		sockets = append(sockets, i)
	}
	return held, sockets
}

func TestHeldSweepP99CountsMissingAnswersAsSlowest(t *testing.T) {
	held, sockets := heldOf(100)
	for _, test := range []struct {
		name    string
		rtt     map[int]time.Duration
		wantP99 time.Duration // MaxInt64 = infinite
	}{
		{"all fast", nil, time.Millisecond},
		{"one slow in a hundred is the 1%", map[int]time.Duration{7: 900 * time.Millisecond}, time.Millisecond},
		{"two slow", map[int]time.Duration{7: 900 * time.Millisecond, 8: 300 * time.Millisecond}, 300 * time.Millisecond},
		{"one missing, one slow", map[int]time.Duration{7: -1, 8: 300 * time.Millisecond}, 300 * time.Millisecond},
		{"two missing", map[int]time.Duration{7: -1, 8: -1}, time.Duration(math.MaxInt64)},
	} {
		var tally sweepTally
		if err := tallySweep(&tally, held, sockets, sweepOf(held, sockets, time.Millisecond, test.rtt, nil)); err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		if got := tally.percentile(0.99); got != test.wantP99 {
			t.Fatalf("%s: p99 %v, want %v", test.name, got, test.wantP99)
		}
		missing := 0
		for _, d := range test.rtt {
			if d < 0 {
				missing++
			}
		}
		if tally.held != 100 || tally.answered != 100-missing {
			t.Fatalf("%s: held %d answered %d", test.name, tally.held, tally.answered)
		}
	}
}

func TestHeldSweepCatchesAnotherSessionAndShortAnswers(t *testing.T) {
	held, sockets := heldOf(10)
	var tally sweepTally
	if err := tallySweep(&tally, held, sockets, sweepOf(held, sockets, time.Millisecond, nil, map[int]string{4: "192.0.2.1:9999"})); err != nil {
		t.Fatal(err)
	}
	if tally.wrongSource != 1 || tally.answered != 10 {
		t.Fatalf("a new engine socket for a held session must count as another session: %+v", tally)
	}
	short := sweepOf(held, sockets, time.Millisecond, nil, nil)
	short.RTTMicros = short.RTTMicros[:9]
	if err := tallySweep(&sweepTally{}, held, sockets, short); err == nil {
		t.Fatal("a sweep result missing a socket's timing was accepted")
	}
	reordered := sweepOf(held, sockets, time.Millisecond, nil, nil)
	reordered.Sockets = append([]int{1, 0}, sockets[2:]...)
	if err := tallySweep(&sweepTally{}, held, sockets, reordered); err == nil {
		t.Fatal("a sweep result for other sockets was accepted")
	}
	if p := (sweepTally{}).percentile(0.99); p != time.Duration(math.MaxInt64) {
		t.Fatalf("an empty sweep has p99 %v; it must never pass", p)
	}
}

// heldPool is a recorded pool of n sessions: flow IDs, app sources, and the
// engine's flows by app source, all unchanged.
func heldPool(n int) (ids map[int]string, locals []string, now map[string]engine.Flow) {
	ids, now = map[int]string{}, map[string]engine.Flow{}
	for i := range n {
		local := fmt.Sprintf("10.0.0.2:%d", 40000+i)
		ids[i] = strconv.Itoa(100 + i)
		locals = append(locals, local)
		now[local] = engine.Flow{ID: ids[i], Protocol: "udp", Source: netip.MustParseAddrPort(local)}
	}
	return ids, locals, now
}

// The review's false pass: a session dropped and recreated during the sweep
// with the same outbound address and port answers from the same source and
// leaves the count unchanged. Only its new flow ID and the new admission
// show it.
func TestHeldSweepCatchesSessionReplacedWithSameSource(t *testing.T) {
	const n = 10
	held, sockets := heldOf(n)
	for _, test := range []struct {
		name     string
		edit     func(ids map[int]string, now map[string]engine.Flow, locals []string, after *engine.Stats)
		failures []string
	}{
		{"continuous", func(map[int]string, map[string]engine.Flow, []string, *engine.Stats) {}, nil},
		{"replaced with the same source", func(_ map[int]string, now map[string]engine.Flow, locals []string, after *engine.Stats) {
			f := now[locals[4]]
			f.ID = "9999"
			now[locals[4]] = f
			after.Admitted++ // the replacement was a new admission
		}, []string{"still the engine flow recorded", "no new admission"}},
		{"replaced, admission hidden", func(_ map[int]string, now map[string]engine.Flow, locals []string, _ *engine.Stats) {
			f := now[locals[4]]
			f.ID = "9999"
			now[locals[4]] = f
		}, []string{"still the engine flow recorded"}},
		{"gone", func(_ map[int]string, now map[string]engine.Flow, locals []string, _ *engine.Stats) {
			delete(now, locals[2])
		}, []string{"still the engine flow recorded"}},
		{"never recorded", func(ids map[int]string, _ map[string]engine.Flow, _ []string, _ *engine.Stats) {
			delete(ids, 7)
		}, []string{"still the engine flow recorded"}},
		{"refused during the sweep", func(_ map[int]string, _ map[string]engine.Flow, _ []string, after *engine.Stats) {
			after.RefusedUDP.UDP++
		}, []string{"no new admission"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ids, locals, now := heldPool(n)
			before := engine.Stats{UDP: n, Admitted: 500}
			after := before
			test.edit(ids, now, locals, &after)
			var tally sweepTally
			// Every echo answers fast from its held source: the old checks pass.
			if err := tallySweep(&tally, held, sockets, sweepOf(held, sockets, time.Millisecond, nil, nil)); err != nil {
				t.Fatal(err)
			}
			sweepContinuity(&tally, ids, locals, sockets, now)
			report := runHardCheck(t, func(e *Env) { e.sweepVerdict("sweep", tally, time.Second, before, after) })
			if len(test.failures) == 0 {
				if report.JobFailed {
					t.Fatalf("a continuous pool failed: %+v", report.Cases[0])
				}
				return
			}
			for _, failure := range test.failures {
				requireFailure(t, report, failure)
			}
			for _, check := range report.Cases[0].Checks {
				if !check.OK && (strings.Contains(check.Message, "answered one echo") || strings.Contains(check.Message, "neither added nor lost")) {
					t.Fatalf("the replacement was meant to pass the old source and count checks: %+v", check)
				}
			}
		})
	}
}
