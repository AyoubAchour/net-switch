//go:build linux

package suite

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"slices"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/app"
	"github.com/AyoubAchour/net-switch/tests/linux/engine"
)

// Section 5.9, "Held sessions stay responsive": at the UDP cap, an echo
// through every held session, 32 at a time, has p99 at most 250 ms, and the
// whole sweep takes at most 30 s, a tenth of the 5-minute idle timeout. The
// apps sweep one after another, each 32 at a time, so no more than 32 echoes
// are ever in flight in total. Each echo goes once; a missing answer counts
// as an infinitely slow one, never a retry.
const (
	sweepConcurrency = 32
	sweepP99Limit    = 250 * time.Millisecond
	sweepWholeLimit  = 30 * time.Second
	// An echo still unanswered after this is a failure, whatever the p99.
	sweepEchoTimeout = 2 * time.Second
	// Echoes not started within twice the whole-sweep limit are reported as
	// unsent, so a stalled engine fails within a bounded time.
	sweepBudget = 2 * sweepWholeLimit
)

// sweepFile is one app's sweep request path, next to the case's release.
func sweepFile(release Release, name string) string {
	return string(release) + ".sweep-" + name
}

// sweepTally is the sweep's evidence for a set of held sessions.
type sweepTally struct {
	held, answered int
	// wrongSource counts answers the server saw from another source than the
	// session's first datagram: a new engine socket, so not the held session.
	wrongSource, unsent, stale, maxInFlight int
	errors                                  map[string]int
	rtts                                    []time.Duration // answered echoes only
	appTime                                 time.Duration
}

// tallySweep checks one app's sweep result against the sessions the servers
// saw it hold (socket index -> the source the server saw).
func tallySweep(t *sweepTally, held map[int]string, sockets []int, res app.SweepResult) error {
	if len(res.Sockets) != len(sockets) || len(res.RTTMicros) != len(sockets) || len(res.Seen) != len(sockets) || !slices.Equal(res.Sockets, sockets) {
		return fmt.Errorf("sweep answered for %d sockets (%d timings, %d sources), asked for %d", len(res.Sockets), len(res.RTTMicros), len(res.Seen), len(sockets))
	}
	if t.errors == nil {
		t.errors = map[string]int{}
	}
	for k, i := range sockets {
		t.held++
		if res.RTTMicros[k] < 0 {
			continue
		}
		t.answered++
		t.rtts = append(t.rtts, time.Duration(res.RTTMicros[k])*time.Microsecond)
		if res.Seen[k] != held[i] {
			t.wrongSource++
		}
	}
	for code, n := range res.Errors {
		t.errors[code] += n
	}
	t.unsent += res.Unsent
	t.stale += res.Stale
	t.maxInFlight = max(t.maxInFlight, res.MaxInFlight)
	t.appTime += time.Duration(res.DurationUS) * time.Microsecond
	return nil
}

// percentile is the nearest-rank percentile over every held session's echo;
// an unanswered echo ranks as infinitely slow.
func (t sweepTally) percentile(p float64) time.Duration {
	if t.held == 0 {
		return time.Duration(math.MaxInt64)
	}
	rank := int(math.Ceil(p*float64(t.held))) - 1
	if rank >= len(t.rtts) {
		return time.Duration(math.MaxInt64)
	}
	sorted := slices.Clone(t.rtts)
	slices.Sort(sorted)
	return sorted[max(0, rank)]
}

func ms(d time.Duration) float64 {
	if d == time.Duration(math.MaxInt64) {
		return math.Inf(1)
	}
	return float64(d.Microseconds()) / 1000
}

// heldSweep runs the gate over the apps' held UDP sessions: every socket
// whose first datagram reached a server and wasn't refused. It also checks
// that the sweep neither added nor lost an engine UDP session.
func (e *Env) heldSweep(label string, names []string, bgs map[string]*Bg, release Release, results map[string]app.FloodResult, all map[string]sessions, s engine.Controller) {
	before := stats(e, s)
	var t sweepTally
	start := time.Now()
	for _, name := range names {
		refused := map[int]bool{}
		for _, i := range results[name].RefusedSockets {
			refused[i] = true
		}
		var sockets []int
		for i := range all[name].serverSrc {
			if !refused[i] {
				sockets = append(sockets, i)
			}
		}
		slices.Sort(sockets)
		req, err := json.Marshal(app.SweepRequest{Sockets: sockets, Concurrency: sweepConcurrency,
			EchoTimeoutMS: int(sweepEchoTimeout / time.Millisecond), BudgetMS: int(sweepBudget / time.Millisecond)})
		e.T.Require(err == nil, "%s: encode %s's sweep request (%v)", label, name, err)
		path := sweepFile(release, name)
		err = os.WriteFile(path+".tmp", req, 0o644)
		if err == nil {
			err = os.Rename(path+".tmp", path)
		}
		e.T.Require(err == nil, "%s: hand %s its sweep request (%v)", label, name, err)
		var res app.SweepResult
		bgs[name].WaitHeld(e, "sweep", sweepBudget+time.Minute, &res)
		e.T.Require(res.Token == results[name].Token, "%s: %s's sweep answers for its own flood (%q, flood %q)", label, name, res.Token, results[name].Token)
		err = tallySweep(&t, all[name].serverSrc, sockets, res)
		e.T.Require(err == nil, "%s: %s's sweep reports every requested socket (%v)", label, name, err)
	}
	wall := time.Since(start)
	after := stats(e, s)
	p99 := t.percentile(0.99)
	e.T.Logf("HELD SWEEP %s: sessions=%d answered=%d wrong-source=%d unsent=%d errors=%v stale=%d concurrency=%d max-in-flight=%d p50=%.3fms p95=%.3fms p99=%.3fms max=%.3fms wall=%.3fs app-sum=%.3fs engine-UDP=%d->%d",
		label, t.held, t.answered, t.wrongSource, t.unsent, t.errors, t.stale, sweepConcurrency, t.maxInFlight,
		ms(t.percentile(0.50)), ms(t.percentile(0.95)), ms(p99), ms(t.percentile(1)), wall.Seconds(), t.appTime.Seconds(), before.UDP, after.UDP)
	e.T.Check(t.held > 0 && t.answered == t.held && t.wrongSource == 0 && t.unsent == 0,
		"%s: every one of the %d held UDP sessions answered one echo through its original engine socket (%d answered, %d from another source, %d unsent, errors %v)",
		label, t.held, t.answered, t.wrongSource, t.unsent, t.errors)
	e.T.Check(t.held > 0 && p99 <= sweepP99Limit && t.maxInFlight <= sweepConcurrency,
		"%s: held-session echo p99 is at most 250 ms, %d at a time (%.3f ms over %d echoes, at most %d in flight)", label, sweepConcurrency, ms(p99), t.held, t.maxInFlight)
	e.T.Check(wall <= sweepWholeLimit, "%s: the sweep through all %d held sessions finished within 30 s, a tenth of the UDP idle timeout (%.3f s)", label, t.held, wall.Seconds())
	e.T.Check(after.UDP == before.UDP, "%s: the sweep neither added nor lost an engine UDP session (%d before, %d after)", label, before.UDP, after.UDP)
}
