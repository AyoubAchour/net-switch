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
	add("protocol.lease-fencing", "A newer controller fences the old one: its renewals and commands are refused", "2, 5.9, 5.10", 0, leaseFencing)
	add("protocol.reattach-within-lease", "Control stops renewing; the engine keeps forwarding, and a new controller reattaches with the same instance and revision", "2, 3.3", 0, reattachWithinLease)
	add("protocol.lease-lapse-cleans-up", "When the lease lapses the engine stops, cleans up and exits; normal internet works again", "2", 2*time.Minute, leaseLapse)
	add("protocol.flows-pagination", "flows{cursor} pages through 300 held connections over several pages, each exactly once, with its tuple, app, lane, line, revision, epoch and pid", "5.10", 0, flowsPagination)
	add("protocol.snapshot-budget", "Four flow snapshots at once: a fifth is refused for capacity until one finishes, and snapshots lapse after 10 s", "5.9, 5.10", 0, snapshotBudget)
	add("protocol.totals-include-closed", "totals count bytes of flows that have already closed, per app and per line", "5.10", 0, totalsIncludeClosed)
	add("protocol.closeflows-started-before", "closeFlows with startedBefore closes only flows admitted before a revision, and repeating it is safe", "3.3, 4.6, 5.10", 0, closeStartedBefore)
	add("protocol.predict-keeps-counter", "predict gives a shared app's distribution without advancing the combining counter", "5.4, 5.10", 0, predictKeepsCounter)
	add("protocol.lookup-counters", "stats counts ambiguous owners and records lookup time", "5.6, 5.10", 0, lookupCounters)
	add("protocol.probe-per-line", "A probe tests the physical line, not its lane, and repeating its operation id returns the recorded result", "4.5, 5.10", 0, probePerLine)
	add("protocol.https-probe-validation", "Full probes validate TLS and operator bodies, require HTTP/2 for Quad9, and refuse redirects and login portals", "4.5", 0, httpsProbes)
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

// applied is the revision in effect, or stops the case.
func (e *Env) applied(v1 engine.V1) engine.Applied {
	h := e.hello(v1)
	e.T.Require(h.Applied != nil, "the started engine reports the revision in effect")
	return *h.Applied
}

func revisions(e *Env) {
	cfg := e.DefaultConfig()
	e.StartEngine(cfg)
	v1, s := e.v1()
	loaded := e.applied(v1)
	next := cfg
	next.Policy.Pins = append(append([]engine.Pin{}, cfg.Policy.Pins...), engine.Pin{App: e.App("delta"), Line: "c"})
	n := loaded.N + 1
	first, err := s.Apply(e.Ctx(), n, next)
	e.T.Require(err == nil && first.N == n && first.Hash != "" && first.Point > loaded.Point,
		"revision %d is applied and acknowledged with its hash and a later apply point (%+v after %+v, %v)", n, first, loaded, err)
	again, err := s.Apply(e.Ctx(), n, next)
	e.T.Check(err == nil && again.Revision == first.Revision, "sending the same n and config again is a success (%+v, %v)", again, err)
	other := next
	other.Policy.IPv6 = !other.Policy.IPv6
	_, err = s.Apply(e.Ctx(), n, other)
	e.T.Check(engine.RefusedWith(err, engine.RefusedConflict), "the same n with another config is refused as a conflict (%v)", err)
	_, err = s.Apply(e.Ctx(), loaded.N, cfg)
	e.T.Check(engine.RefusedWith(err, engine.RefusedStale), "a lower n is refused as stale (%v)", err)
	now := e.applied(v1)
	e.T.Check(now.Revision == first.Revision, "the revision in effect is still %d (%+v)", n, now)
	e.ExpectTCP(fmt.Sprintf("delta follows revision %d", n), "delta", AsUser, "c", topo.Server4, 3)
}

func leaseFencing(e *Env) {
	e.StartEngine(e.DefaultConfig())
	v1, old := e.v1()
	fresh, err := v1.Attach(e.Ctx())
	e.T.Require(err == nil, "a second controller attaches (%v)", err)
	h := e.hello(v1)
	e.T.Check(fresh.Epoch() > old.Epoch() && fresh.InstanceID() == old.InstanceID() && h.Epoch == fresh.Epoch(),
		"the engine handed out a higher epoch for the same instance (%d after %d; hello says %d)", fresh.Epoch(), old.Epoch(), h.Epoch)
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
	before := e.applied(v1)
	instance := e.hello(v1).InstanceID
	stream := e.StartStream("bravo", AsUser, 20*time.Second)
	// Control "crashes": no more renewals.
	old.SetAutoRenew(false)
	e.Sleep(12 * time.Second)
	e.ExpectTCP("charlie, 12 s into the unrenewed lease", "charlie", AsUser, "c", topo.Server4, 3)
	fresh, err := v1.Attach(e.Ctx())
	e.T.Require(err == nil, "a restarted controller reattaches within the lease (%v)", err)
	after := e.hello(v1)
	e.T.Check(after.InstanceID == instance && fresh.Epoch() > old.Epoch(), "the same engine instance, with a new epoch (%s, %d after %d)", after.InstanceID, fresh.Epoch(), old.Epoch())
	e.T.Check(after.Applied != nil && *after.Applied == before, "the revision in effect survived (%+v, was %+v)", after.Applied, before)
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

// holdConns starts an app holding n connections to the hold server until
// the returned barrier opens, and returns their addresses as the app sees
// them.
func (e *Env) holdConns(name string, n int, release Release) (*Bg, app.HeldList) {
	args := append([]string{"tcphold", "--to", To(topo.Server4, wire.PortHold), "--count", fmt.Sprint(n), "--concurrency", "50", "--timeout", "5000", "--tuples"}, release.Arg()...)
	hold := e.Start(Run{App: name, Args: args})
	var held app.HeldList
	hold.WaitHeld(e, "held", 60*time.Second, &held)
	e.T.Require(held.Established == n && len(held.Conns) == n, "%s holds its %d connections (%d)", name, n, held.Established)
	return hold, held
}

func flowsPagination(e *Env) {
	const n = 300
	e.StartEngine(e.DefaultConfig())
	v1, s := e.v1()
	loaded := e.applied(v1)
	release := e.NewRelease("pages")
	hold, held := e.holdConns("bravo", n, release)
	want := map[string]bool{}
	for _, c := range held.Conns {
		want[c.Local+" "+c.Remote] = true
	}
	e.T.Require(len(want) == n, "bravo's %d connections have %d distinct tuples", n, len(want))

	// Every page of one snapshot, from the protocol itself: no other listing
	// is consulted, and every flow is identified by its tuple, not its label.
	type got struct {
		f    engine.Flow
		page int
	}
	matched := map[string][]got{}
	ids := map[string]int{}
	var cursors []string
	var sizes []int
	var wrong, stray []string
	cursor := ""
	for page := 1; ; page++ {
		e.T.Require(page <= 1000, "the cursor ends within 1,000 pages")
		p, err := s.Flows(e.Ctx(), cursor)
		e.T.Require(err == nil, "page %d of flows (%v)", page, err)
		sizes = append(sizes, len(p.Flows))
		for _, f := range p.Flows {
			ids[f.ID]++
			key := f.Source.String() + " " + f.Destination.String()
			switch {
			case want[key]:
				matched[key] = append(matched[key], got{f, page})
				if f.Protocol != "tcp" || f.App != AppPath("bravo") || f.PID != hold.Pid() || f.Lane != "b" || f.Line != "b" ||
					f.Revision != loaded.N || f.Epoch != s.Epoch() || f.Point <= loaded.Point {
					wrong = append(wrong, fmt.Sprintf("%s: %s app %q pid %d lane %s line %s revision %d epoch %d point %d", key, f.Protocol, f.App, f.PID, f.Lane, f.Line, f.Revision, f.Epoch, f.Point))
				}
			case f.App == AppPath("bravo") || f.Destination.Port() == wire.PortHold:
				stray = append(stray, fmt.Sprintf("%s %s %q", f.Protocol, key, f.App))
			}
		}
		if p.Next == "" {
			break
		}
		e.T.Require(len(p.Flows) > 0, "page %d has flows before its cursor (%d)", page, len(p.Flows))
		for _, c := range cursors {
			e.T.Require(c != p.Next, "page %d's cursor %q is new, not one already followed", page, p.Next)
		}
		cursors = append(cursors, p.Next)
		cursor = p.Next
	}
	e.T.Require(hold.Running(), "bravo still holds its connections after the listing")
	once, twice := 0, 0
	for _, list := range matched {
		if len(list) == 1 {
			once++
		} else {
			twice++
		}
	}
	dupIDs := 0
	for _, count := range ids {
		if count > 1 {
			dupIDs++
		}
	}
	e.T.Check(len(sizes) >= 2 && len(cursors) == len(sizes)-1,
		"%d flows came over %d pages, each but the last ending in a new cursor (page sizes %v)", n, len(sizes), sizes)
	e.T.Check(once == n && twice == 0 && dupIDs == 0,
		"each of bravo's %d held connections was listed exactly once, by its own tuple (once %d, more than once %d, missing %d, ids listed twice %d)", n, once, twice, n-len(matched), dupIDs)
	e.T.Check(len(wrong) == 0, "every held connection says tcp, bravo, its pid, lane b, line b, revision %d, epoch %d and a point after the revision's (%d didn't: %s)",
		loaded.N, s.Epoch(), len(wrong), strings.Join(upTo(wrong, 3), "; "))
	e.T.Check(len(stray) == 0, "no flow claims bravo or the hold server besides the held connections (%s)", strings.Join(upTo(stray, 3), "; "))
	release.Open(e)
	var r app.HoldResult
	hold.WaitJSON(e, 30*time.Second, &r)
	e.T.Check(r.StillOpen == n, "all %d connections were still open at the end (%d)", n, r.StillOpen)
}

// upTo is the first n of a list, and how many more there are.
func upTo(list []string, n int) []string {
	if len(list) > n {
		return append(list[:n:n], fmt.Sprintf("... %d more", len(list)-n))
	}
	return list
}

func snapshotBudget(e *Env) {
	e.StartEngine(e.DefaultConfig())
	_, s := e.v1()
	release := e.NewRelease("snapshots")
	hold, _ := e.holdConns("bravo", 200, release)
	var open []string
	for i := 1; i <= 4; i++ {
		p, err := s.Flows(e.Ctx(), "")
		e.T.Require(err == nil && p.Next != "", "snapshot %d starts, with more pages to come (%v)", i, err)
		open = append(open, p.Next)
	}
	_, err := s.Flows(e.Ctx(), "")
	e.T.Check(engine.RefusedWith(err, engine.RefusedCapacity), "a fifth snapshot while four are open is refused for capacity (%v)", err)
	cursor := open[0]
	for cursor != "" {
		p, err := s.Flows(e.Ctx(), cursor)
		e.T.Require(err == nil, "following snapshot 1 to its end (%v)", err)
		cursor = p.Next
	}
	_, err = s.Flows(e.Ctx(), "")
	e.T.Check(err == nil, "with snapshot 1 finished, a new snapshot starts (%v)", err)
	// Every snapshot now open lapses 10 s after it started.
	e.Sleep(11 * time.Second)
	_, err = s.Flows(e.Ctx(), open[1])
	e.T.Check(err != nil && !engine.RefusedWith(err, engine.RefusedCapacity), "an 11 s old cursor is no longer valid (%v)", err)
	started := 0
	for range 4 {
		if p, err := s.Flows(e.Ctx(), ""); err == nil && p.Next != "" {
			started++
		}
	}
	e.T.Check(started == 4, "once the old snapshots lapse, four new ones start (%d)", started)
	release.Open(e)
	hold.Wait(e, 30*time.Second)
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
	// The app has closed its connection; the engine lets go of it shortly
	// after. Poll until it does, within a bound.
	left, gone := e.WaitNoFlow(5*time.Second, func(f engine.Flow) bool { return f.App == AppPath("charlie") })
	e.T.Require(gone, "within 5 s the engine no longer lists charlie's finished transfer (%d left)", len(left))
	after, err := s.Totals(e.Ctx())
	e.T.Require(err == nil, "totals (%v)", err)
	app := after.PerApp[e.App("charlie").Key()].Down - before.PerApp[e.App("charlie").Key()].Down
	line := after.PerLine["c"].Down - before.PerLine["c"].Down
	e.T.Check(app >= size && line >= size, "the closed transfer's 1 MiB is in charlie's total (+%d) and line c's (+%d)", app, line)
}

func closeStartedBefore(e *Env) {
	cfg := e.DefaultConfig()
	e.StartEngine(cfg)
	v1, s := e.v1()
	loaded := e.applied(v1)
	isStream := func(rev uint64) func(engine.Flow) bool {
		return func(f engine.Flow) bool {
			return f.App == AppPath("bravo") && f.Destination.Port() == wire.PortStream && f.Revision == rev
		}
	}
	older := e.StartStream("bravo", AsUser, 12*time.Second)
	oldFlow, ok := e.WaitFlow(3*time.Second, isStream(loaded.N))
	e.T.Require(ok, "bravo's first stream is admitted under revision %d", loaded.N)
	next := cfg
	next.Policy.Pins = append(append([]engine.Pin{}, cfg.Policy.Pins...), engine.Pin{App: e.App("delta"), Line: "b"})
	ack, err := s.Apply(e.Ctx(), loaded.N+1, next)
	e.T.Require(err == nil && ack.N == loaded.N+1 && ack.Point > oldFlow.Point, "revision %d is acknowledged with an apply point after the first stream's (%+v, flow point %d, %v)", loaded.N+1, ack, oldFlow.Point, err)
	newer := e.StartStream("bravo", AsUser, 10*time.Second)
	newFlow, ok := e.WaitFlow(3*time.Second, isStream(ack.N))
	e.T.Require(ok && newFlow.Point > ack.Point, "bravo's second stream is admitted under revision %d, after its apply point (%d)", ack.N, newFlow.Point)
	res, err := s.CloseFlows(e.Ctx(), "op-close-1", engine.Selector{Line: "b"}, ack.Point)
	e.T.Require(err == nil, "closeFlows (%v)", err)
	again, err := s.CloseFlows(e.Ctx(), "op-close-1", engine.Selector{Line: "b"}, ack.Point)
	e.T.Check(err == nil && res == again, "repeating the operation id returns the recorded result (%+v, then %+v, %v)", res, again, err)
	e.T.Check(res.Closed == 1, "exactly the older flow was closed (%+v)", res)
	var so, sn Stream
	older.WaitJSON(e, 30*time.Second, &so)
	newer.WaitJSON(e, 30*time.Second, &sn)
	e.T.Check(so.ClosedAt != 0, "flow %s, admitted before revision %d, was closed (%q)", oldFlow.ID, ack.N, so.CloseErr)
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
	var p engine.Prediction
	var err error
	for range 10 {
		if p, err = s.Predict(e.Ctx(), e.App("alpha")); err != nil {
			e.T.Fatalf("predict: %v", err)
		}
	}
	e.T.Check(math.Abs(p.Distribution["a"]-2.0/3) < 0.01 && math.Abs(p.Distribution["b"]-1.0/3) < 0.01, "predict for unpinned alpha is the share distribution (%+v)", p)
	pinned, err := s.Predict(e.Ctx(), e.App("bravo"))
	if err != nil {
		e.T.Fatalf("predict: %v", err)
	}
	e.T.Check(pinned.Line == "b" && pinned.Distribution == nil && !pinned.Blocked, "predict for pinned bravo is its lane target b (%+v)", pinned)
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
	e.T.Check(after.LookupCount >= 1 && after.LookupTime > 0, "lookup time is recorded (%d lookups, %v in total, mean %v)", after.LookupCount, after.LookupTime, after.LookupMean())
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
	okA, err := s.Probe(e.Ctx(), "probe-a", "a", "quick:cloudflare")
	e.T.Check(err == nil && okA.OK, "line a's probe passes (%+v, %v)", okA, err)
	failB, err := s.Probe(e.Ctx(), "probe-b", "b", "quick:cloudflare")
	e.T.Check(err == nil && !failB.OK && failB.Error != "", "line b's probe fails though b's lane points at a (%+v, %v)", failB, err)
	again, err := s.Probe(e.Ctx(), "probe-b", "b", "quick:cloudflare")
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
