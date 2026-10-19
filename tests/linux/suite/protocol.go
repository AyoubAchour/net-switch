//go:build linux

package suite

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/app"
	"github.com/AyoubAchour/net-switch/tests/linux/engine"
	"github.com/AyoubAchour/net-switch/tests/linux/harness"
	"github.com/AyoubAchour/net-switch/tests/linux/inet"
	"github.com/AyoubAchour/net-switch/tests/linux/topo"
	"github.com/AyoubAchour/net-switch/tests/linux/wire"
)

func init() { register(60, addProtocol) }

// Cases that need 1.0's control protocol (5.10). They never run on the
// baseline; on 1.0 they must pass.
func addProtocol(r *registry) {
	add := func(id, title, spec string, timeout time.Duration, fn caseFunc) {
		r.add(id, title, harness.Requires10, spec, timeout, fn)
	}
	add("protocol.revisions", "Revisions: the same n and hash is idempotent, the same n with another hash conflicts, a lower n is stale", "3.3, 5.10", 0, revisions)
	add("protocol.lease-fencing", "A newer controller fences the old one: its renewals and commands are refused", "2, 5.10", 0, leaseFencing)
	add("protocol.reattach-within-lease", "Control stops renewing; the engine keeps forwarding, and a new controller reattaches with the same instance and revision", "2, 3.3", 0, reattachWithinLease)
	add("protocol.lease-lapse-cleans-up", "When the lease lapses the engine stops, cleans up and exits; normal internet works again", "2", 2*time.Minute, leaseLapse)
	add("protocol.flows-pagination", "flows{cursor} pages through 300 open flows exactly once each, with lane, line, revision and epoch", "5.10", 0, flowsPagination)
	add("protocol.totals-include-closed", "totals count bytes of flows that have already closed, per app and per line", "5.10", 0, totalsIncludeClosed)
	add("protocol.closeflows-started-before", "closeFlows with startedBefore closes only flows admitted before a revision, and repeating it is safe", "3.3, 4.6, 5.10", 0, closeStartedBefore)
	add("protocol.predict-keeps-counter", "predict gives a shared app's distribution without advancing the combining counter", "5.4, 5.10", 0, predictKeepsCounter)
	add("protocol.lookup-counters", "stats counts ambiguous owners and records lookup latency", "5.6, 5.10", 0, lookupCounters)
	add("protocol.probe-quick-per-line", "A quick probe tests the physical line, not its lane, and repeating its operation id returns the recorded result", "4.5, 5.10", 0, probePerLine)
	add("udp.identity-without-notifications", "UDP port reuse is caught within 1 s with destroy notifications dropped or delayed, for an opposite pin and a blocked line", "5.3", 3*time.Minute, udpIdentityWithoutNotifications)
}

func (e *Env) v1() (engine.V1, engine.Controller) {
	v1, ok := e.Eng.(engine.V1)
	if !ok {
		e.T.Fatalf("this engine's driver doesn't implement the 1.0 protocol (engine.V1)")
	}
	s := v1.Session()
	if s == nil {
		e.T.Fatalf("the engine has no control session")
	}
	return v1, s
}

func (e *Env) hello(v1 engine.V1) engine.Hello {
	h, err := v1.Hello(e.Ctx())
	if err != nil {
		e.T.Fatalf("hello: %v", err)
	}
	return h
}

func revisions(e *Env) {
	cfg := e.DefaultConfig()
	e.StartEngine(cfg)
	v1, s := e.v1()
	loaded := e.hello(v1).LoadedRevision
	e.T.Require(loaded != nil, "the started engine reports a loaded revision")
	next := cfg
	next.Policy.Pins = append(next.Policy.Pins, engine.Pin{App: e.App("delta"), Line: "c"})
	rev := engine.Revision{N: loaded.N + 1, Hash: engine.RevisionHash(next)}
	first, err := s.Apply(e.Ctx(), rev, next)
	e.T.Require(err == nil && first.Applied == rev, "revision %d is applied and acknowledged (%+v, %v)", rev.N, first, err)
	again, err := s.Apply(e.Ctx(), rev, next)
	e.T.Check(err == nil && again.Applied == rev, "sending the same n and hash again is a success (%+v, %v)", again, err)
	other := next
	other.Policy.IPv6 = !other.Policy.IPv6
	_, err = s.Apply(e.Ctx(), engine.Revision{N: rev.N, Hash: engine.RevisionHash(other)}, other)
	e.T.Check(engine.RefusedWith(err, engine.RefusedConflict), "the same n with another hash is refused as a conflict (%v)", err)
	_, err = s.Apply(e.Ctx(), engine.Revision{N: loaded.N, Hash: loaded.Hash}, cfg)
	e.T.Check(engine.RefusedWith(err, engine.RefusedStale), "a lower n is refused as stale (%v)", err)
	now := e.hello(v1).LoadedRevision
	e.T.Check(now != nil && *now == rev, "the loaded revision is still %d (%+v)", rev.N, now)
	e.ExpectTCP("delta follows revision "+fmt.Sprint(rev.N), "delta", AsUser, "c", topo.Server4, 3)
}

func leaseFencing(e *Env) {
	e.StartEngine(e.DefaultConfig())
	v1, old := e.v1()
	fresh, err := v1.Attach(e.Ctx())
	e.T.Require(err == nil, "a second controller attaches (%v)", err)
	e.T.Check(fresh.Epoch() > old.Epoch() && fresh.InstanceID() == old.InstanceID(),
		"the engine handed out a higher epoch for the same instance (%d after %d)", fresh.Epoch(), old.Epoch())
	e.T.Check(engine.RefusedWith(old.Renew(e.Ctx()), engine.RefusedFenced), "the old controller's renewal is refused as fenced")
	_, err = old.Flows(e.Ctx(), "")
	e.T.Check(engine.RefusedWith(err, engine.RefusedFenced), "the old controller's commands are refused as fenced (%v)", err)
	e.T.Check(fresh.Renew(e.Ctx()) == nil, "the new controller renews")
	_, err = fresh.Flows(e.Ctx(), "")
	e.T.Check(err == nil, "the new controller's commands work (%v)", err)
	e.ExpectTCP("routing carries on", "bravo", AsUser, "b", topo.Server4, 3)
}

func reattachWithinLease(e *Env) {
	cfg := e.DefaultConfig()
	e.StartEngine(cfg)
	v1, old := e.v1()
	before := e.hello(v1)
	stream := e.StartStream("bravo", AsUser, 20*time.Second)
	// Control "crashes": no more renewals.
	old.SetAutoRenew(false)
	e.Sleep(12 * time.Second)
	e.ExpectTCP("charlie, 12 s into the unrenewed lease", "charlie", AsUser, "c", topo.Server4, 3)
	fresh, err := v1.Attach(e.Ctx())
	e.T.Require(err == nil, "a restarted controller reattaches within the lease (%v)", err)
	after := e.hello(v1)
	e.T.Check(after.InstanceID == before.InstanceID && fresh.Epoch() > old.Epoch(), "the same engine instance, with a new epoch (%s, %d after %d)", after.InstanceID, fresh.Epoch(), old.Epoch())
	e.T.Check(after.LoadedRevision != nil && before.LoadedRevision != nil && *after.LoadedRevision == *before.LoadedRevision,
		"the loaded revision survived (%+v, was %+v)", after.LoadedRevision, before.LoadedRevision)
	fresh.SetAutoRenew(true)
	var s Stream
	stream.WaitJSON(e, 40*time.Second, &s)
	e.CheckStreamSurvived("bravo's stream across the controller restart", s, "b")
	e.T.Check(e.Eng.Running(), "the engine never stopped")
}

func leaseLapse(e *Env) {
	e.StartEngine(e.DefaultConfig())
	v1, s := e.v1()
	e.ExpectTCP("bravo while attached", "bravo", AsUser, "b", topo.Server4, 3)
	s.SetAutoRenew(false)
	start := time.Now()
	err := v1.WaitExit(e.Ctx())
	gone := time.Since(start)
	e.T.Check(err == nil && gone >= 25*time.Second && gone <= 45*time.Second, "the engine exits when the 30 s lease lapses (after %s, %v)", gone.Round(time.Second), err)
	e.ExpectSameState("after the lapse", e.Before)
	e.ExpectTCP("bravo after the lapse (normal routing)", "bravo", AsUser, "a", topo.Server4, 3)
}

func flowsPagination(e *Env) {
	e.StartEngine(e.DefaultConfig())
	v1, s := e.v1()
	hold := e.Start(Run{App: "bravo", Args: []string{"tcphold", "--to", To(topo.Server4, wire.PortStream), "--count", "300", "--concurrency", "50", "--hold", "15000"}})
	hold.WaitOutput(e, "holding 300", 30*time.Second)
	loaded := e.hello(v1).LoadedRevision
	seen := map[string]bool{}
	pages, dup, bad := 0, 0, 0
	cursor := ""
	for {
		page, err := s.Flows(e.Ctx(), cursor)
		e.T.Require(err == nil, "page %d of flows (%v)", pages+1, err)
		pages++
		for _, f := range page.Flows {
			if seen[f.ID] {
				dup++
			}
			seen[f.ID] = true
			if f.App == AppPath("bravo") && (f.Line != "b" || f.Lane != "b" || loaded == nil || f.Revision != loaded.N || f.Epoch == 0 || f.PID == 0) {
				bad++
			}
		}
		if page.Next == "" || pages > 10000 {
			break
		}
		cursor = page.Next
	}
	count := len(seen)
	held := 0
	all, err := e.Eng.Flows(e.Ctx())
	e.T.Require(err == nil, "listing flows (%v)", err)
	for _, f := range all {
		if f.App == AppPath("bravo") && f.Destination.Port() == wire.PortStream {
			held++
		}
	}
	e.T.Check(held >= 300 && count >= 300 && dup == 0, "%d pages listed %d flows once each (bravo's held flows: %d; duplicates %d)", pages, count, held, dup)
	e.T.Check(bad == 0, "every bravo flow says lane b, line b, the loaded revision, an epoch and a pid (%d didn't)", bad)
	hold.Stop()
}

func totalsIncludeClosed(e *Env) {
	e.StartEngine(e.DefaultConfig())
	_, s := e.v1()
	before, err := s.Totals(e.Ctx())
	e.T.Require(err == nil, "totals (%v)", err)
	const size = 1 << 20
	var r app.BulkResult
	e.RunJSON(Run{App: "charlie", Args: []string{"bulk", "--to", To(topo.Server4, wire.PortBulk), "--bytes", fmt.Sprint(size)}}, &r)
	e.T.Require(r.OK, "charlie downloaded 1 MiB (%s)", r.Err)
	_, open := e.WaitFlow(0, func(f engine.Flow) bool { return f.App == AppPath("charlie") })
	e.T.Check(!open, "charlie's transfer has closed")
	after, err := s.Totals(e.Ctx())
	e.T.Require(err == nil, "totals (%v)", err)
	app := after.PerApp[AppPath("charlie")].Down - before.PerApp[AppPath("charlie")].Down
	line := after.PerLine["c"].Down - before.PerLine["c"].Down
	e.T.Check(app >= size && line >= size, "the closed transfer's 1 MiB is in charlie's total (+%d) and line c's (+%d)", app, line)
}

func closeStartedBefore(e *Env) {
	cfg := e.DefaultConfig()
	e.StartEngine(cfg)
	v1, s := e.v1()
	loaded := e.hello(v1).LoadedRevision
	e.T.Require(loaded != nil, "the started engine reports a loaded revision")
	isStream := func(rev int64) func(engine.Flow) bool {
		return func(f engine.Flow) bool {
			return f.App == AppPath("bravo") && f.Destination.Port() == wire.PortStream && f.Revision == rev
		}
	}
	older := e.StartStream("bravo", AsUser, 12*time.Second)
	oldFlow, ok := e.WaitFlow(3*time.Second, isStream(loaded.N))
	e.T.Require(ok, "bravo's first stream is admitted under revision %d", loaded.N)
	next := cfg
	next.Policy.Pins = append(next.Policy.Pins, engine.Pin{App: e.App("delta"), Line: "b"})
	rev := engine.Revision{N: loaded.N + 1, Hash: engine.RevisionHash(next)}
	ack, err := s.Apply(e.Ctx(), rev, next)
	e.T.Require(err == nil && ack.Applied == rev && ack.ApplyPoint > 0, "revision %d is acknowledged with an apply point (%+v, %v)", rev.N, ack, err)
	newer := e.StartStream("bravo", AsUser, 10*time.Second)
	newFlow, ok := e.WaitFlow(3*time.Second, isStream(rev.N))
	e.T.Require(ok, "bravo's second stream is admitted under revision %d", rev.N)
	res, err := s.CloseFlows(e.Ctx(), "op-close-1", engine.Selector{Line: "b"}, ack.ApplyPoint)
	e.T.Require(err == nil, "closeFlows (%v)", err)
	again, err := s.CloseFlows(e.Ctx(), "op-close-1", engine.Selector{Line: "b"}, ack.ApplyPoint)
	e.T.Check(err == nil && res == again, "repeating the operation id returns the recorded result (%+v, then %+v, %v)", res, again, err)
	e.T.Check(res.Closed == 1, "exactly the older flow was closed (%+v)", res)
	var so, sn Stream
	older.WaitJSON(e, 30*time.Second, &so)
	newer.WaitJSON(e, 30*time.Second, &sn)
	e.T.Check(so.ClosedAt != 0, "flow %s, admitted before revision %d, was closed (%q)", oldFlow.ID, rev.N, so.CloseErr)
	e.CheckStreamSurvived("flow "+newFlow.ID+", admitted after the revision", sn, "b")
}

func predictKeepsCounter(e *Env) {
	cfg := e.DefaultConfig()
	cfg.Policy.Combine = true
	cfg.Policy.Shares = map[engine.LineID]float64{"a": 2.0 / 3, "b": 1.0 / 3}
	e.StartEngine(cfg)
	_, s := e.v1()
	stats := func() engine.Stats {
		st, err := s.Stats(e.Ctx())
		if err != nil {
			e.T.Fatalf("stats: %v", err)
		}
		return st
	}
	before := stats()
	var dist map[engine.LineID]float64
	var err error
	for range 10 {
		if dist, err = s.Predict(e.Ctx(), e.App("alpha")); err != nil {
			e.T.Fatalf("predict: %v", err)
		}
	}
	e.T.Check(math.Abs(dist["a"]-2.0/3) < 0.01 && math.Abs(dist["b"]-1.0/3) < 0.01, "predict for unpinned alpha is the share distribution (%v)", dist)
	pinned, err := s.Predict(e.Ctx(), e.App("bravo"))
	if err != nil {
		e.T.Fatalf("predict: %v", err)
	}
	e.T.Check(len(pinned) == 1 && pinned["b"] == 1, "predict for pinned bravo is its lane target b (%v)", pinned)
	mid := stats()
	e.T.Check(mid.Admitted == before.Admitted, "11 predictions left the counter at %d (now %d)", before.Admitted, mid.Admitted)
	e.TCP("alpha", AsUser, "--to", To(topo.Server4, wire.PortWhoami), "--count", "3")
	after := stats()
	e.T.Check(after.Admitted == mid.Admitted+3, "3 admitted connections advanced the counter by 3 (%d -> %d)", mid.Admitted, after.Admitted)
}

func lookupCounters(e *Env) {
	r := e.shared(true, []string{"bravo", "charlie"})
	_, s := e.v1()
	after, err := s.Stats(e.Ctx())
	e.T.Require(err == nil, "stats (%v)", err)
	e.T.Check(topo.LineOfText(r.Seen) == "a", "the ambiguous socket went to the main line (%q)", topo.LineOfText(r.Seen))
	e.T.Check(after.LookupAmbiguous >= 1, "the ambiguous owner was counted (%d)", after.LookupAmbiguous)
	p95, known := after.LookupLatency.Quantile(0.95)
	e.T.Check(after.LookupLatency.Total() >= 1 && known && p95 > 0, "lookup latency is recorded (%d lookups, p95 %v)", after.LookupLatency.Total(), p95)
}

func probePerLine(e *Env) {
	e.StartEngine(e.DefaultConfig())
	_, s := e.v1()
	// b's router loses the internet and b's lane is pointed at a: a probe of
	// line b must still test b itself.
	if err := e.Net.UplinkDown(e.Ctx(), "b"); err != nil {
		e.T.Fatalf("%v", err)
	}
	e.SetLanes(map[engine.LineID]engine.LineID{"b": "a"})
	since := time.Now().UnixMilli()
	okA, err := s.Probe(e.Ctx(), "probe-a", "a", "cloudflare", "quick")
	e.T.Check(err == nil && okA.Outcome == "ok", "line a's quick probe passes (%+v, %v)", okA, err)
	failB, err := s.Probe(e.Ctx(), "probe-b", "b", "cloudflare", "quick")
	e.T.Check(err == nil && failB.Outcome == "lineFailed", "line b's quick probe fails though b's lane points at a (%+v, %v)", failB, err)
	again, err := s.Probe(e.Ctx(), "probe-b", "b", "cloudflare", "quick")
	e.T.Check(err == nil && again == failB, "repeating the operation id returns the recorded result (%+v, %v)", again, err)
	probes := Select(e.Records(), func(r inet.Record) bool { return r.Kind == "tcp" && r.T >= since && strings.HasSuffix(r.Dst, ":443") })
	e.T.Check(len(probes) == 1 && topo.LineOfText(probes[0].Src) == "a", "the probe servers saw exactly one probe, line a's (%d, lines %s)", len(probes), Describe(RecordLines(probes)))
}

// udpIdentityWithoutNotifications: 5.3's reuse test with the fast path off,
// so only the 1 s reconciliation can catch the new owner.
func udpIdentityWithoutNotifications(e *Env) {
	for _, fault := range []engine.Fault{
		{Kind: "udp-destroy-notifications", Mode: "drop"},
		{Kind: "udp-destroy-notifications", Mode: "delay", Delay: 3 * time.Second},
	} {
		for _, blocked := range []bool{false, true} {
			cfg := e.DefaultConfig()
			second, want := "charlie", engine.LineID("c")
			if blocked {
				second = "delta"
				cfg.Policy.Pins = append(cfg.Policy.Pins, engine.Pin{App: e.App("delta"), Line: "c"})
				cfg.Policy.Blocked = []engine.LineID{"c"}
			}
			label := fmt.Sprintf("%s %s, %s reuses the port", fault.Mode, fault.Kind, second)
			e.StartEngine(cfg)
			_, s := e.v1()
			ack, err := s.InjectFault(e.Ctx(), fault)
			e.T.Require(err == nil && ack.Active, "%s: the engine confirms the fault is active (%+v, %v)", label, ack, err)
			target := To(topo.Server4, wire.PortUDPEcho)
			var first app.UDPStreamResult
			e.RunJSON(Run{App: "bravo", Args: []string{"udpstream", "--to", target, "--local-port", "40125", "--duration", "1500", "--rate", "50"}}, &first)
			firstLines := Lines(eventsSeen(first.Replies))
			e.T.Require(len(first.Replies) > 40 && firstLines["b"] == len(first.Replies), "%s: bravo's live mapping is on b first (%s)", label, Describe(firstLines))
			var next app.UDPStreamResult
			e.RunJSON(Run{App: second, Args: []string{"udpstream", "--to", target, "--local-port", "40125", "--duration", "3000", "--rate", "50", "--connect"}}, &next)
			settle := next.StartedAt + 1000
			e.Sleep(500 * time.Millisecond)
			late := Select(Select(e.Records(), Tagged("udp", next.Token)), func(r inet.Record) bool { return r.T >= settle })
			if blocked {
				refused := 0
				for _, ev := range append(next.RecvErrors, next.SendErrors...) {
					if ev.What == "ECONNREFUSED" && ev.T >= settle {
						refused++
					}
				}
				e.T.Check(len(late) == 0 && refused > 0, "%s: after 1 s nothing of %s's gets out and it's refused (%d arrived, refused %d times)", label, second, len(late), refused)
			} else {
				lines := RecordLines(late)
				e.T.Check(len(late) >= 50 && lines[want] == len(late), "%s: after 1 s all of %s's datagrams use line %s (%s)", label, second, want, Describe(lines))
			}
			e.StopEngine()
		}
	}
}
