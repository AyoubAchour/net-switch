//go:build linux

package suite

import (
	"math"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/app"
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
