//go:build linux

package suite

import (
	"math"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/app"
	"github.com/AyoubAchour/net-switch/tests/linux/engine"
	"github.com/AyoubAchour/net-switch/tests/linux/harness"
	"github.com/AyoubAchour/net-switch/tests/linux/topo"
	"github.com/AyoubAchour/net-switch/tests/linux/wire"
)

func init() { register(60, addProtocol) }

// Cases that need 1.0's control protocol (5.10). They never run on the
// baseline; on 1.0 they must pass.
func addProtocol(r *registry) {
	r.add("protocol.closeflows-started-before", "closeFlows with startedBefore closes only flows admitted before a revision, and repeating it is safe", harness.Requires10, "3.3, 4.6, 5.10", 0, closeStartedBefore)
	r.add("protocol.predict-keeps-counter", "predict gives a shared app's distribution without advancing the combining counter", harness.Requires10, "5.4, 5.10", 0, predictKeepsCounter)
	r.add("protocol.lookup-counters", "stats counts ambiguous owners and reports lookup latency", harness.Requires10, "5.6, 5.10", 0, lookupCounters)
	r.add("udp.identity-bound-without-notifications", "UDP port reuse is caught within 1 s even with socket-destroy notifications dropped or delayed", harness.Requires10, "5.3", 0, udpIdentityWithoutNotifications)
}

func (e *Env) v1() engine.V1 {
	v1, ok := e.Eng.(engine.V1)
	if !ok {
		e.T.Fatalf("this engine's driver doesn't implement the 1.0 protocol (engine.V1)")
	}
	return v1
}

func closeStartedBefore(e *Env) {
	v1 := e.v1()
	e.StartEngine(e.DefaultConfig())
	older := e.StartStream("bravo", AsUser, 10*time.Second)
	e.Sleep(time.Second)
	p := e.DefaultConfig().Policy
	p.Pins = append(p.Pins, engine.Pin{App: e.App("delta"), Line: "b"})
	e.Apply(p)
	rev, _, err := v1.Revision(e.Ctx())
	if err != nil {
		e.T.Fatalf("revision: %v", err)
	}
	newer := e.StartStream("bravo", AsUser, 8*time.Second)
	e.Sleep(time.Second)
	res, err := v1.CloseFlowsBefore(e.Ctx(), "op-close-1", engine.Selector{Line: "b"}, rev)
	if err != nil {
		e.T.Fatalf("closeFlows: %v", err)
	}
	again, err := v1.CloseFlowsBefore(e.Ctx(), "op-close-1", engine.Selector{Line: "b"}, rev)
	if err != nil {
		e.T.Fatalf("closeFlows again: %v", err)
	}
	e.T.Check(res == again, "repeating the operation id returns the recorded result (%+v, then %+v)", res, again)
	var so, sn Stream
	older.WaitJSON(e, 20*time.Second, &so)
	newer.WaitJSON(e, 20*time.Second, &sn)
	e.T.Check(so.ClosedAt != 0, "the flow admitted before revision %d was closed (%q)", rev, so.CloseErr)
	e.CheckStreamSurvived("the flow admitted after the revision", sn, "b")
}

func predictKeepsCounter(e *Env) {
	v1 := e.v1()
	cfg := e.DefaultConfig()
	cfg.Policy.Combine = true
	cfg.Policy.Shares = map[engine.LineID]float64{"a": 2.0 / 3, "b": 1.0 / 3}
	e.StartEngine(cfg)
	before, err := v1.Stats(e.Ctx())
	if err != nil {
		e.T.Fatalf("stats: %v", err)
	}
	var dist map[engine.LineID]float64
	for range 10 {
		if dist, err = v1.Predict(e.Ctx(), e.App("alpha")); err != nil {
			e.T.Fatalf("predict: %v", err)
		}
	}
	e.T.Check(math.Abs(dist["a"]-2.0/3) < 0.01 && math.Abs(dist["b"]-1.0/3) < 0.01, "predict for unpinned alpha is the share distribution (%v)", dist)
	pinned, err := v1.Predict(e.Ctx(), e.App("bravo"))
	if err != nil {
		e.T.Fatalf("predict: %v", err)
	}
	e.T.Check(len(pinned) == 1 && pinned["b"] == 1, "predict for pinned bravo is its lane target b (%v)", pinned)
	mid, err := v1.Stats(e.Ctx())
	if err != nil {
		e.T.Fatalf("stats: %v", err)
	}
	e.T.Check(mid.Admitted == before.Admitted, "11 predictions left the counter at %d (now %d)", before.Admitted, mid.Admitted)
	e.TCP("alpha", AsUser, "--to", To(topo.Server4, wire.PortWhoami), "--count", "3")
	after, err := v1.Stats(e.Ctx())
	if err != nil {
		e.T.Fatalf("stats: %v", err)
	}
	e.T.Check(after.Admitted == mid.Admitted+3, "3 admitted connections advanced the counter by 3 (%d -> %d)", mid.Admitted, after.Admitted)
}

func lookupCounters(e *Env) {
	v1 := e.v1()
	e.StartEngine(e.DefaultConfig())
	before, err := v1.Stats(e.Ctx())
	if err != nil {
		e.T.Fatalf("stats: %v", err)
	}
	var r app.FDResult
	e.RunJSON(Run{App: "bravo", Args: []string{"share-exec", "--to", To(topo.Server4, wire.PortWhoami), "--child", AppPath("charlie"), "--keep=true"}}, &r)
	after, err := v1.Stats(e.Ctx())
	if err != nil {
		e.T.Fatalf("stats: %v", err)
	}
	e.T.Check(after.LookupAmbiguous > before.LookupAmbiguous, "the ambiguous owner was counted (%d -> %d)", before.LookupAmbiguous, after.LookupAmbiguous)
	e.T.Check(after.LookupP95 > 0, "lookup latency is reported (p95 %s)", after.LookupP95)
}

func udpIdentityWithoutNotifications(e *Env) {
	v1 := e.v1()
	for _, fault := range []string{"udp-destroy-drop", "udp-destroy-delay"} {
		e.StartEngine(e.DefaultConfig())
		if err := v1.InjectFault(e.Ctx(), fault); err != nil {
			e.T.Fatalf("fault %s: %v", fault, err)
		}
		target := To(topo.Server4, wire.PortUDPEcho)
		var first, next app.UDPStreamResult
		e.RunJSON(Run{App: "bravo", Args: []string{"udpstream", "--to", target, "--local-port", "40125", "--duration", "1500", "--rate", "50"}}, &first)
		e.RunJSON(Run{App: "charlie", Args: []string{"udpstream", "--to", target, "--local-port", "40125", "--duration", "3000", "--rate", "50", "--connect"}}, &next)
		late, total := 0, 0
		for _, ev := range next.Replies {
			if ev.T >= next.StartedAt+1000 {
				total++
				if topo.LineOfText(ev.What) == "c" {
					late++
				}
			}
		}
		e.T.Check(total >= 50 && late == total, "with %s, charlie's datagrams 1 s after taking the port are all on c (%d of %d)", fault, late, total)
		e.StopEngine()
	}
}
