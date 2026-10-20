//go:build linux

package suite

import (
	"context"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/app"
	"github.com/AyoubAchour/net-switch/tests/linux/engine"
	"github.com/AyoubAchour/net-switch/tests/linux/harness"
	"github.com/AyoubAchour/net-switch/tests/linux/topo"
	"github.com/AyoubAchour/net-switch/tests/linux/wire"
)

func init() {
	register(56, func(r *registry) {
		r.add("capacity.mixed-caps", "49,152 TCP flows, 16,384 UDP sessions and 4,096 TIME_WAIT endpoints held together stay within 512 MiB", harness.Requires10, "5.9", 8*time.Minute, mixedCaps)
	})
}

func (e *Env) memorySample(s engine.Controller, label string) engine.Stats {
	profiler, ok := e.Eng.(interface{ CaptureProfiles(context.Context) error })
	e.T.Require(ok, "capacity engine supports held heap/goroutine profiles")
	ctx, cancel := context.WithTimeout(e.Ctx(), 20*time.Second)
	err := profiler.CaptureProfiles(ctx)
	cancel()
	e.T.Require(err == nil, "%s: collect the live heap before releasing any socket (%v)", label, err)
	st := stats(e, s)
	e.T.Logf("%s: flows=%d UDP=%d TIME_WAIT=%d heap=%d stack=%d managed=%d goroutines=%d GC-CPU-ppm=%d TCP-growth=%d relay=%d reply=%d pending=%d",
		label, st.Flows, st.UDP, st.TimeWait, st.Counters["heapBytes"], st.Counters["stackBytes"], st.Counters["runtimeBytes"],
		st.Counters["goroutines"], st.Counters["gcCPUppm"], st.TCPBytes, st.Counters["tcpRelayBytes"], st.UDPReplyBytes, st.PendingBytes)
	return st
}

func mixedCaps(e *Env) {
	// The total flow limit includes UDP. Filling both §5.9 caps therefore
	// means 65,536 - 16,384 TCP flows, plus the separately capped TIME_WAIT.
	cfg := e.DefaultConfig()
	cfg.Policy.Pins = nil
	for _, name := range AppNames {
		cfg.Policy.Pins = append(cfg.Policy.Pins, engine.Pin{App: e.App(name), Line: "c"})
	}
	e.raiseConntrack(1 << 20)
	e.StartEngine(cfg)
	_, s := e.v1()
	baseline := e.memorySample(s, "MIXED BASELINE")
	release := e.NewRelease("mixed")
	// Match the proven UDP-total fixture: 20,000 offered sockets, each app
	// below its own cap. 30,000 exceeds the DUT's native ephemeral port pool.
	udpNames := AppNames[:5]
	e.T.Logf("MIXED OFFER: 20,000 UDP sockets; native ephemeral range %s", e.SysctlDUT("net.ipv4.ip_local_port_range"))
	udpApps, udpResults := e.udpFlood(udpNames, 4000, release)
	udpStats := e.memorySample(s, "MIXED UDP HELD")
	e.T.Require(udpStats.UDP == udpSessionsTotal && udpStats.Flows == udpSessionsTotal,
		"the UDP cap is held before adding TCP (%d sessions, %d flows)", udpStats.UDP, udpStats.Flows)
	e.floodSessions(udpNames, udpResults)
	e.T.Logf("MIXED UDP COST: heap/session=%.2f managed/session=%.2f stack/session=%.2f",
		float64(int64(udpStats.Counters["heapBytes"])-int64(baseline.Counters["heapBytes"]))/udpSessionsTotal,
		float64(int64(udpStats.Counters["runtimeBytes"])-int64(baseline.Counters["runtimeBytes"]))/udpSessionsTotal,
		float64(int64(udpStats.Counters["stackBytes"])-int64(baseline.Counters["stackBytes"]))/udpSessionsTotal)

	// Fill retained endpoints immediately before the TCP wave; all must
	// still be present in the measured mixed plateau.
	tw := e.TCP("kilo", AsUser, "--to", To(topo.Server4, wire.PortWhoami), "--count", "5000", "--concurrency", "8", "--timeout", "5000")
	e.T.Require(tw.OK == 5000, "all TIME_WAIT fixture connections completed (%d, %v)", tw.OK, tw.Errors)
	deadline := time.Now().Add(5 * time.Second)
	for {
		st := stats(e, s)
		if (st.TimeWait == 4096 && st.Flows == udpSessionsTotal) || !time.Now().Before(deadline) {
			break
		}
		e.Sleep(20 * time.Millisecond)
	}
	withTW := e.memorySample(s, "MIXED UDP AND TIME_WAIT HELD")
	e.T.Require(withTW.TimeWait == 4096 && withTW.Flows == udpSessionsTotal, "4,096 TIME_WAIT endpoints are retained outside live capacity (%d / %d)", withTW.TimeWait, withTW.Flows)
	tcpApps := map[string]*Bg{}
	held := map[string]app.HeldList{}
	for i, name := range AppNames {
		tcpApps[name] = e.Start(Run{App: name, Args: append([]string{"tcphold", "--to", floodTargets(i, wire.PortHold), "--count", "8000", "--concurrency", "100", "--timeout", "10000", "--tuples", "--probe"}, release.Arg()...)})
	}
	total := 0
	for _, name := range AppNames {
		var list app.HeldList
		tcpApps[name].WaitHeld(e, "held", 3*time.Minute, &list)
		held[name] = list
		total += list.Established
		e.T.Logf("MIXED TCP OFFER %s: held=%d errors=%v failure-ms=%+v", name, list.Established, list.Errors, list.FailedMS)
	}
	// Still fail unless the exact cap is held, but preserve the profile and
	// live accounting when a holder is missing so the failure is diagnosable.
	e.T.Check(total == tcpFlowsTotal-udpSessionsTotal, "the TCP holders fill exactly the remaining 49,152 slots (%d)", total)
	for name, bg := range udpApps {
		e.T.Require(bg.Running(), "%s still holds its UDP sockets at the mixed cap", name)
	}
	full := e.memorySample(s, "MIXED ALL CAPS HELD")
	for i := 0; i < 3; i++ {
		if i != 0 {
			e.Sleep(time.Second)
			full = stats(e, s)
		}
		e.T.Check(full.Flows == tcpFlowsTotal && full.UDP == udpSessionsTotal && full.TimeWait == 4096,
			"mixed plateau %d holds both live caps and every TIME_WAIT endpoint (%d/%d/%d)", i, full.Flows, full.UDP, full.TimeWait)
		e.T.Check(full.Counters["runtimeBytes"] <= 512<<20,
			"mixed plateau %d stays within 512 MiB including stacks, GC metadata and retained endpoints (%d bytes)", i, full.Counters["runtimeBytes"])
		e.T.Check(full.Counters["goroutines"] < 256, "mixed plateau has bounded shared workers (%d goroutines)", full.Counters["goroutines"])
	}
	e.T.Logf("MIXED TCP COST: heap/flow=%.2f managed/flow=%.2f stack/flow=%.2f; TIME_WAIT heap/endpoint=%.2f; GC-window-ns=%d total-CPU-window-ns=%d; TUN=%s output-drops=%d",
		float64(int64(full.Counters["heapBytes"])-int64(withTW.Counters["heapBytes"]))/float64(total),
		float64(int64(full.Counters["runtimeBytes"])-int64(withTW.Counters["runtimeBytes"]))/float64(total),
		float64(int64(full.Counters["stackBytes"])-int64(withTW.Counters["stackBytes"]))/float64(total),
		float64(int64(withTW.Counters["heapBytes"])-int64(udpStats.Counters["heapBytes"]))/4096,
		full.Counters["gcCPUNanos"]-baseline.Counters["gcCPUNanos"], full.Counters["totalCPUNanos"]-baseline.Counters["totalCPUNanos"], full.TunKernel, full.Counters["tunDropped"])
	e.checkHeldTCP(held, tcpApps)
	release.Open(e)
	for _, name := range AppNames {
		var result app.HoldResult
		tcpApps[name].WaitJSON(e, 2*time.Minute, &result)
		e.T.Check(result.StillOpen == held[name].Established, "%s's mixed-cap TCP flows survived (%d/%d)", name, result.StillOpen, held[name].Established)
	}
	for _, bg := range udpApps {
		bg.Wait(e, time.Minute)
	}
}
