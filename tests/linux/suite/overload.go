//go:build linux

package suite

import (
	"fmt"
	"strings"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/app"
	"github.com/AyoubAchour/net-switch/tests/linux/topo"
	"github.com/AyoubAchour/net-switch/tests/linux/wire"
)

// Section 5.9's Linux budgets. An engine with no admission limits must fail
// these cases, and the baseline is one: that's the defect they record.
const (
	udpSessionsPerApp = 4096
	udpSessionsTotal  = 16384
	tcpFlowsPerApp    = 8192
)

func init() { register(55, addOverload) }

func addOverload(r *registry) {
	const noLimits = "sing-box has no per-app or total admission limits: it admits every session and connection it's asked for"
	r.defect("overload.udp-sessions", "20,000 UDP sessions from 4 apps: each app gets at most 4,096 and the total stays under 16,384, while other traffic carries on",
		noLimits, "5.9", 3*time.Minute, udpSessions)
	r.defect("overload.tcp-connection-storm", "A storm of 9,000 connections from one app: at most 8,192 are admitted, the rest refused, while other apps carry on",
		noLimits, "5.9", 3*time.Minute, tcpStorm)
}

func udpSessions(e *Env) {
	e.StartEngine(e.DefaultConfig())
	stream := e.StartStream("charlie", AsUser, 25*time.Second)
	e.Sleep(time.Second)
	const perApp = 5000
	floods := map[string]*Bg{}
	for i, name := range []string{"alpha", "bravo", "charlie", "delta"} {
		var dests []string
		for _, addr := range topo.ManyServers()[i*10 : i*10+10] {
			dests = append(dests, To(addr, wire.PortUDPEcho))
		}
		// 800 new sessions a second per app: the excess arrives within the
		// 1,000/s budget for refusal notices (5.9), so every one can be told.
		floods[name] = e.Start(Run{App: name, Args: []string{"udpflood", "--to", strings.Join(dests, ","), "--sockets", fmt.Sprint(perApp), "--rate", "800", "--timeout", "4000"}})
	}
	e.Sleep(3 * time.Second)
	e.ExpectTCP("foxtrot during the flood", "foxtrot", AsUser, "a", topo.Server4, 3)
	total := 0
	var counts []string
	minAnswered, maxAnswered, minRefused := perApp, 0, perApp
	for _, name := range []string{"alpha", "bravo", "charlie", "delta"} {
		var r app.FloodResult
		floods[name].WaitJSON(e, 90*time.Second, &r)
		e.T.Check(r.Opened == perApp && len(r.OpenErrors) == 0, "%s opened its %d sockets (%d, errors %v)", name, perApp, r.Opened, r.OpenErrors)
		total += r.Answered
		minAnswered, maxAnswered, minRefused = min(minAnswered, r.Answered), max(maxAnswered, r.Answered), min(minRefused, r.Refused)
		counts = append(counts, fmt.Sprintf("%s %d answered, %d refused, %d silent", name, r.Answered, r.Refused, r.Silent))
	}
	e.T.Check(minAnswered >= udpSessionsPerApp*95/100, "every app still got at least 95%% of its allowed %d sessions served (least: %d; %s)", udpSessionsPerApp, minAnswered, strings.Join(counts, "; "))
	var s Stream
	stream.WaitJSON(e, 40*time.Second, &s)
	e.CheckStreamSurvived("charlie's stream through the flood", s, "c")
	e.T.Check(e.Eng.Running(), "the engine is still running")
	// Losing sessions at random isn't a limit: the excess must be refused.
	excess := perApp - udpSessionsPerApp
	e.T.Expect(maxAnswered <= udpSessionsPerApp && total <= udpSessionsTotal && minRefused >= excess*9/10,
		"no app gets more than %d sessions, all together no more than %d, and each app's %d extra sessions are refused (most for one app %d, total %d, fewest refused %d; %s)",
		udpSessionsPerApp, udpSessionsTotal, excess, maxAnswered, total, minRefused, strings.Join(counts, "; "))
}

func tcpStorm(e *Env) {
	e.StartEngine(e.DefaultConfig())
	stream := e.StartStream("charlie", AsUser, 30*time.Second)
	e.Sleep(time.Second)
	const storm = 9000
	hold := e.Start(Run{App: "bravo", Args: []string{"tcphold", "--to", To(topo.Server4, wire.PortStream), "--count", fmt.Sprint(storm), "--concurrency", "300", "--timeout", "5000", "--hold", "6000"}})
	hold.WaitLine(e, "holding ", 2*time.Minute)
	e.ExpectTCP("foxtrot during the storm", "foxtrot", AsUser, "a", topo.Server4, 3)
	var r app.HoldResult
	hold.WaitJSON(e, 60*time.Second, &r)
	refused := r.Errors["ECONNREFUSED"] + r.Errors["ECONNRESET"]
	e.T.Check(r.Established >= tcpFlowsPerApp*95/100, "bravo still got at least 95%% of its allowed %d connections (%d established, errors %v)", tcpFlowsPerApp, r.Established, r.Errors)
	e.T.Check(r.StillOpen == r.Established, "admitted connections stay open (%d of %d)", r.StillOpen, r.Established)
	var s Stream
	stream.WaitJSON(e, 60*time.Second, &s)
	e.CheckStreamSurvived("charlie's stream through the storm", s, "c")
	e.T.Check(e.Eng.Running(), "the engine is still running")
	e.T.Expect(r.Established <= tcpFlowsPerApp && refused == storm-r.Established && r.FailedMS.Max < 3000,
		"at most %d of %d are admitted and every other one is refused within 3 s (%d admitted, %d refused, slowest refusal %.0f ms, errors %v)",
		tcpFlowsPerApp, storm, r.Established, refused, r.FailedMS.Max, r.Errors)
}
