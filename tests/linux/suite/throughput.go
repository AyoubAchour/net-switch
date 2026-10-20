//go:build linux

package suite

import (
	"fmt"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/app"
	"github.com/AyoubAchour/net-switch/tests/linux/harness"
	"github.com/AyoubAchour/net-switch/tests/linux/topo"
	"github.com/AyoubAchour/net-switch/tests/linux/wire"
)

func init() {
	register(57, func(r *registry) {
		r.add("performance.two-cpu-and-dns", "One and eight bulk streams on two CPUs retain throughput and every concurrent DNS reply", harness.Requires10, "5.9, 10", 3*time.Minute, twoCPUThroughput)
	})
}

func throughputWave(e *Env, count int, dns bool, label string) float64 {
	release := e.NewRelease(label)
	var apps []*Bg
	for i := 0; i < count; i++ {
		apps = append(apps, e.Start(Run{App: "alpha", Args: append([]string{"bulkhold", "--to", To(topo.Server4, wire.PortBulk), "--flood", "5000"}, release.Arg()...)}))
	}
	start := time.Now()
	if dns {
		_, s := e.v1()
		before := stats(e, s)
		e.Sleep(250 * time.Millisecond)
		for i := 0; i < 30; i++ {
			var reply app.DNSResult
			e.RunJSON(Run{App: "bravo", Args: []string{"dns", "--server", To(topo.Server4, wire.PortDNS), "--name", "whoami.test", "--type", "A"}}, &reply)
			e.T.Check(reply.Err == "" && len(reply.Addresses) == 1, "DNS reply %d arrives during the bulk download (%s)", i, reply.Err)
		}
		after := stats(e, s)
		e.T.Check(time.Since(start) < 5*time.Second, "all DNS requests ran during the offered bulk window (%s)", time.Since(start))
		e.T.Check(after.Counters["tunDropped.udp"] == before.Counters["tunDropped.udp"], "bulk traffic dropped no DNS packets (%d)", after.Counters["tunDropped.udp"]-before.Counters["tunDropped.udp"])
		e.T.Logf("%s bulk data drops=%d TCP control drops=%d", label, after.Counters["tunDropped.tcpData"]-before.Counters["tunDropped.tcpData"], after.Counters["tunDropped.tcpControl"]-before.Counters["tunDropped.tcpControl"])
	}
	if remaining := 5500*time.Millisecond - time.Since(start); remaining > 0 {
		e.Sleep(remaining)
	}
	release.Open(e)
	var bytes int64
	for i, bg := range apps {
		var result app.BulkHoldResult
		bg.WaitJSON(e, time.Minute, &result)
		e.T.Check(result.Intact && result.Open && result.BurstBytes > 0, "%s stream %d stayed intact and open (%d bytes, %s)", label, i, result.BurstBytes, result.Err)
		bytes += result.BurstBytes
	}
	mbps := float64(bytes) * 8 / 5 / 1e6
	e.T.Logf("%s: %d streams, %d bytes in 5 s, %.2f Mbit/s", label, count, bytes, mbps)
	return mbps
}

func twoCPUThroughput(e *Env) {
	native := map[int]float64{}
	for _, count := range []int{1, 8} {
		native[count] = throughputWave(e, count, false, fmt.Sprintf("native-%d", count))
	}
	e.engineCPUs = 2
	e.StartEngine(e.DefaultConfig())
	_, s := e.v1()
	e.T.Require(stats(e, s).Counters["gomaxprocs"] == 2, "two-CPU benchmark uses exactly two Go processors")
	for _, count := range []int{1, 8} {
		before := stats(e, s)
		rate := throughputWave(e, count, true, fmt.Sprintf("engine-two-cpu-%d", count))
		after := stats(e, s)
		e.T.Logf("TWO CPU RESULT: streams=%d native=%.2f engine=%.2f Mbit/s ratio=%.4f GC-CPU-ns=%d total-CPU-ns=%d managed=%d",
			count, native[count], rate, rate/native[count], after.Counters["gcCPUNanos"]-before.Counters["gcCPUNanos"], after.Counters["totalCPUNanos"]-before.Counters["totalCPUNanos"], after.Counters["runtimeBytes"])
		// A fixed floor catches a crippled worker path; the native comparison
		// is reported independently so a slow runner cannot manufacture a pass.
		e.T.Check(rate >= 100, "two CPUs sustain at least 100 Mbit/s with %d streams (%.2f)", count, rate)
	}
}
