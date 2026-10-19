//go:build linux

package suite

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/app"
	"github.com/AyoubAchour/net-switch/tests/linux/engine"
	"github.com/AyoubAchour/net-switch/tests/linux/topo"
	"github.com/AyoubAchour/net-switch/tests/linux/wire"
)

func fault(e *Env, s engine.Controller, kind, mode string) {
	a, err := s.InjectFault(e.Ctx(), engine.Fault{Kind: kind, Mode: mode})
	e.T.Require(err == nil && a.Active, "engine acknowledged %s %s (%+v, %v)", kind, mode, a, err)
}
func stats(e *Env, s engine.Controller) engine.Stats {
	v, err := s.Stats(e.Ctx())
	e.T.Require(err == nil, "read engine budgets (%v)", err)
	return v
}
func queueSender(e *Env, release Release, sockets, packets, size int) (*Bg, app.QueueResult) {
	bg := e.Start(Run{App: "alpha", Args: append([]string{"udpqueue", "--to", To(topo.Server4, wire.PortUDPEcho), "--sockets", strconv.Itoa(sockets), "--packets", strconv.Itoa(packets), "--size", strconv.Itoa(size), "--rate", "10000"}, release.Arg()...)})
	var r app.QueueResult
	bg.WaitHeld(e, "", 30*time.Second, &r)
	e.T.Require(r.Opened == sockets && r.Sent == sockets*packets && len(r.Errors) == 0, "the app filled its held sockets (%d opened, %d sent, %v)", r.Opened, r.Sent, r.Errors)
	return bg, r
}
func pendingBytes(e *Env) {
	e.StartEngine(e.DefaultConfig())
	_, s := e.v1()
	stream := e.StartStream("charlie", AsUser, 10*time.Second)
	e.streamUp("charlie", stream)
	fault(e, s, "owner-lookups", "hold")
	release := e.NewRelease("queues")
	small, _ := queueSender(e, release, 1, 100, 64)
	large, _ := queueSender(e, release, 256, 80, 4000)
	st := stats(e, s)
	e.T.Check(st.PendingBytes <= 32<<20 && st.PendingPeakBytes <= 32<<20 && st.PendingPeakBytes >= 31<<20, "pending bytes reach but never exceed 32 MiB (now %d, peak %d)", st.PendingBytes, st.PendingPeakBytes)
	e.T.Check(st.Counters["udpPeakQueuePackets"] == 64, "a pending session fills its 64-packet cap (%d)", st.Counters["udpPeakQueuePackets"])
	peak := st.Counters["udpPeakQueueBytes"]
	e.T.Check(peak <= 256<<10 && peak >= 250<<10, "a pending session fills its 256 KiB byte cap (%d)", peak)
	e.T.Check(st.Counters["udpDropped"] > 1000, "the excess is counted as drops (%d)", st.Counters["udpDropped"])
	fault(e, s, "owner-lookups", "off")
	release.Open(e)
	small.Wait(e, 30*time.Second)
	large.Wait(e, 30*time.Second)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st = stats(e, s)
		if st.PendingBytes == 0 {
			break
		}
		e.Sleep(50 * time.Millisecond)
	}
	e.T.Check(st.PendingBytes == 0, "pending reservations were released (%d)", st.PendingBytes)
	var alive Stream
	stream.WaitJSON(e, 15*time.Second, &alive)
	e.CheckStreamSurvived("existing stream during pending overload", alive, "c")
	e.ExpectTCP("new traffic after pending overload", "bravo", AsUser, "b", topo.Server4, 3)
}
func unknownLimits(e *Env) {
	e.StartEngine(e.DefaultConfig())
	_, s := e.v1()
	fault(e, s, "owner-lookups", "unknown")
	release := e.NewRelease("unknown-tcp")
	bg := e.Start(Run{App: "alpha", Args: append([]string{"tcphold", "--to", To(topo.Server4, wire.PortHold), "--count", "2300", "--concurrency", "50", "--timeout", "5000"}, release.Arg()...)})
	line := bg.WaitLine(e, "holding ", 45*time.Second)
	held, err := strconv.Atoi(strings.TrimPrefix(line, "holding "))
	e.T.Require(err == nil, "TCP holder reports its count (%s)", line)
	st := stats(e, s)
	e.T.Check(held == 2048 && st.Unknown == 2048, "unknown TCP fills exactly 2,048 slots (%d held, %d counted)", held, st.Unknown)
	release.Open(e)
	var tcp app.HoldResult
	bg.WaitJSON(e, 30*time.Second, &tcp)
	e.T.Check(tcp.StillOpen == 2048 && tcp.Errors["ECONNREFUSED"]+tcp.Errors["ECONNRESET"] >= 252, "unknown TCP excess is refused and admitted sockets survive (%+v)", tcp)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st = stats(e, s)
		if st.Unknown == 0 {
			break
		}
		e.Sleep(50 * time.Millisecond)
	}
	e.T.Require(st.Unknown == 0, "TCP slots were released before measuring UDP (%d)", st.Unknown)
	release = e.NewRelease("unknown-udp")
	bgs, results := e.udpFlood([]string{"alpha"}, 700, release)
	st = stats(e, s)
	r := results["alpha"]
	e.T.Check(st.UnknownUDP == 512 && st.Unknown == 512 && r.Answered >= 500 && r.Answered <= 512, "unknown UDP fills 512 sessions (%d counted, %d answered)", st.UnknownUDP, r.Answered)
	e.T.Check(r.Refused >= 188, "unknown UDP excess receives refusal (%d)", r.Refused)
	e.holding(bgs, release)
	fault(e, s, "owner-lookups", "off")
	e.ExpectTCP("normal attribution after unknown overload", "bravo", AsUser, "b", topo.Server4, 3)
}
func tunQueue(e *Env) {
	e.StartEngine(e.DefaultConfig())
	_, s := e.v1()
	fault(e, s, "tun-writer", "hold")
	release := e.NewRelease("tun-queue")
	bg, r := queueSender(e, release, 1, 2500, 64)
	e.Sleep(time.Second)
	st := stats(e, s)
	e.T.Check(st.Counters["tunQueued"] == 1024 && st.Counters["tunPeakQueued"] == 1024, "TUN queue fills exactly 1,024 slots (%d now, %d peak)", st.Counters["tunQueued"], st.Counters["tunPeakQueued"])
	e.T.Check(st.Counters["tunDropped"] >= 1000, "full TUN queue counts dropped replies (%d)", st.Counters["tunDropped"])
	seen := Select(e.Records(), Tagged("udp", r.Token))
	e.T.Check(len(seen) >= 2400, "forwarding continues while TUN writes are stalled (%d of 2,500 reached the server)", len(seen))
	fault(e, s, "tun-writer", "off")
	release.Open(e)
	bg.Wait(e, 30*time.Second)
	e.ExpectTCP("routing after the writer resumes", "bravo", AsUser, "b", topo.Server4, 3)
}
func memoryLimit(e *Env) {
	e.StartEngine(e.DefaultConfig())
	_, s := e.v1()
	stream := e.StartStream("charlie", AsUser, 15*time.Second)
	e.streamUp("charlie", stream)
	fault(e, s, "heap-pressure", "on")
	fault(e, s, "heap-pressure", "collect")
	st := stats(e, s)
	e.T.Check(st.Counters["heapBytes"] >= 512<<20, "the live heap reached the 512 MiB GC target (%d bytes)", st.Counters["heapBytes"])
	e.ExpectTCP("new flows under memory pressure", "bravo", AsUser, "b", topo.Server4, 20)
	e.ExpectUDP("new UDP under memory pressure", "bravo", AsUser, "b", topo.Server4, 20)
	for i := 0; i < 10; i++ {
		st = stats(e, s)
		e.T.Check(st.Counters["heapBytes"] >= 512<<20, "memory pressure remains live during traffic (%d bytes)", st.Counters["heapBytes"])
		e.T.Check(st.TCPBytes <= 256<<20 && st.PendingBytes <= 32<<20, "byte budgets hold under memory pressure (TCP %d, UDP %d)", st.TCPBytes, st.PendingBytes)
		e.Sleep(100 * time.Millisecond)
	}
	fault(e, s, "heap-pressure", "off")
	var alive Stream
	stream.WaitJSON(e, 20*time.Second, &alive)
	e.CheckStreamSurvived(fmt.Sprintf("existing stream at %d MiB", 512), alive, "c")
}
