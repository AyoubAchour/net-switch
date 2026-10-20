//go:build linux

package suite

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/app"
	"github.com/AyoubAchour/net-switch/tests/linux/engine"
	"github.com/AyoubAchour/net-switch/tests/linux/topo"
	"github.com/AyoubAchour/net-switch/tests/linux/wire"
)

// An unknown owner may use the main lane, but a wrong identity or wrong route
// is never an attribution deferral. Callers also compare the independent server
// observation with this exact flow, so two incorrectly swapped routes cannot
// cancel one another in aggregate counts.
func loadFlowLine(f engine.Flow, path string, pid int, want engine.LineID) (engine.LineID, bool, error) {
	known := f.App != ""
	line := want
	if !known {
		line = "a"
		if f.AppID != "" || f.PID != 0 {
			return line, false, fmt.Errorf("partial unknown identity: %+v", f)
		}
	} else if f.App != path || f.AppID != path || f.PID != pid {
		return line, true, fmt.Errorf("wrong app identity: %+v, want %s pid %d", f, path, pid)
	}
	if f.Line != line || f.Lane != line {
		return line, known, fmt.Errorf("wrong route: lane %s line %s, want %s", f.Lane, f.Line, line)
	}
	return line, known, nil
}

func (e *Env) loadLine(name string) engine.LineID {
	for _, pin := range e.engCfg.Policy.Pins {
		if pin.App.Key() == e.App(name).Key() {
			return pin.Line
		}
	}
	return "a"
}

func (e *Env) checkLoadIdentity(ok bool, format string, args ...any) bool {
	if e.deferAttribution {
		return e.T.ReleaseCheck(ok, format, args...)
	}
	return e.T.Check(ok, format, args...)
}

// These small routing probes keep their sockets alive just long enough to
// inspect the production flow snapshot. Their count, connection deadline,
// sequential admission and required server responses stay unchanged. There is
// no retry or inferred identity based on the line that happened to answer.
func (e *Env) expectLoadTCP(label, name string, user User, want engine.LineID, dst netip.Addr, n int) app.TCPResult {
	release := e.NewRelease(fmt.Sprintf("tcp-probe-%d", e.ports(n)))
	bg := e.Start(Run{App: name, User: user, Args: append([]string{"tcphold", "--to", To(dst, wire.PortStream), "--count", strconv.Itoa(n), "--concurrency", "1", "--timeout", "5000", "--probe", "--tuples"}, release.Arg()...)})
	var held app.HeldList
	bg.WaitHeld(e, "held", time.Minute, &held)
	e.T.Check(held.Established == n && len(held.Conns) == n, "%s: all %d TCP probes connected and received their server response (%d)", label, n, held.Established)
	byTuple := map[string]engine.Flow{}
	duplicates := 0
	for _, f := range e.Flows() {
		if f.Protocol == "tcp" {
			key := f.Source.String() + " " + f.Destination.String()
			_, duplicate := byTuple[key]
			if duplicate {
				duplicates++
			}
			byTuple[key] = f
		}
	}
	e.T.Check(duplicates == 0, "held TCP flow tuples are unique (%d duplicates)", duplicates)
	known, invalid := 0, 0
	seen := map[string]int{}
	var attempts []app.Attempt
	for i, c := range held.Conns {
		f, present := byTuple[c.Local+" "+c.Remote]
		line, identified, err := loadFlowLine(f, AppPath(name), bg.Pid(), want)
		if !present || err != nil || topo.LineOfText(c.Seen) != line {
			invalid++
			e.T.Logf("%s probe %s: listed=%t identity/route=%v server=%s required=%s", label, c.Local, present, err, c.Seen, line)
		}
		if identified {
			known++
		}
		seen[c.Seen]++
		local, _ := netip.ParseAddrPort(c.Local)
		attempts = append(attempts, app.Attempt{I: i, To: c.Remote, Seen: c.Seen, Port: int(local.Port()), Connected: true})
	}
	e.T.Check(invalid == 0, "%s: every identified probe uses %s and every explicit unknown uses main, verified against its own server reply (%d invalid)", label, want, invalid)
	e.checkLoadIdentity(known == n, "%s: all %d probe owners are identified (%d identified, %d unknown); original all-on-%s check would pass: %t", label, n, known, len(held.Conns)-known, want, held.Established == n && Lines(seen)[want] == n)
	release.Open(e)
	var result app.HoldResult
	bg.WaitJSON(e, time.Minute, &result)
	e.T.Check(result.Established == n && result.StillOpen == n, "%s: every probe stayed open until inspected (%d of %d)", label, result.StillOpen, n)
	return app.TCPResult{Count: n, OK: result.Established, Errors: result.Errors, Seen: seen, Connect: result.Connect, FailedMS: result.FailedMS, Attempts: attempts}
}

// A load declaration never covers recovery after that load has ended.
func (e *Env) expectRecoveryTCP(label string) {
	e.expectSteadyTCP(label, "bravo", "b", topo.Server4, 3)
}

func (e *Env) withSteadyAttribution(check func()) {
	deferred := e.deferAttribution
	e.deferAttribution = false
	defer func() { e.deferAttribution = deferred }()
	check()
}

func (e *Env) expectSteadyTCP(label, name string, want engine.LineID, dst netip.Addr, count int) {
	e.withSteadyAttribution(func() {
		e.expectLoadTCP(label, name, AsUser, want, dst, count)
	})
}

// Correlate each client's own local/remote tuple, its engine row, the source
// returned over that very connection, and the server's independent accept log.
// Opposite routing mistakes cannot disappear in aggregate line counts.
func (e *Env) checkHeldTCP(held map[string]app.HeldList, apps map[string]*Bg, requireKnown ...string) {
	rows := make(map[string]engine.Flow)
	duplicates := 0
	for _, f := range e.Flows() {
		if f.Protocol == "tcp" {
			key := f.Source.String() + " " + f.Destination.String()
			if _, exists := rows[key]; exists {
				duplicates++
			}
			rows[key] = f
		}
	}
	accepted := make(map[string]int)
	for _, rec := range e.Records() {
		if rec.Kind == "tcp" {
			accepted[rec.Src+" "+rec.Dst]++
		}
	}
	invalid, total := duplicates, 0
	seen := map[string]bool{}
	for name, list := range held {
		appName := apps[name].r.App
		e.T.Check(list.Established == len(list.Conns), "%s reports every held tuple (%d/%d)", name, len(list.Conns), list.Established)
		for _, c := range list.Conns {
			key := c.Local + " " + c.Remote
			f, present := rows[key]
			line, known, err := loadFlowLine(f, AppPath(appName), apps[name].Pid(), e.loadLine(appName))
			serverKey := c.Seen + " " + c.Remote
			if !present || err != nil || topo.LineOfText(c.Seen) != line || accepted[serverKey] != 1 || seen[key] || (!known && slices.Contains(requireKnown, name)) {
				if invalid < 5 {
					e.T.Logf("held tuple %s: present=%t identity=%v server=%s records=%d", key, present, err, c.Seen, accepted[serverKey])
				}
				invalid++
			}
			seen[key] = true
			total++
		}
	}
	e.T.Check(invalid == 0, "all %d held TCP tuples match their own identity, route and server accept record (%d invalid)", total, invalid)
}

func (e *Env) expectLoadUDP(label, name string, user User, want engine.LineID, dst netip.Addr, count int) app.UDPResult {
	release := e.NewRelease(fmt.Sprintf("udp-probe-%d", e.ports(1)))
	bg := e.Start(Run{App: name, User: user, Args: append([]string{"udp", "--to", To(dst, wire.PortUDPEcho), "--count", strconv.Itoa(count)}, release.Arg()...)})
	var result app.UDPResult
	bg.WaitHeld(e, "held", time.Minute, &result)
	e.T.Require(len(result.LocalPorts) == 1, "%s reports its one UDP endpoint (%v)", label, result.LocalPorts)
	var flow engine.Flow
	matched := 0
	for _, f := range e.Flows() {
		if f.Protocol == "udp" && int(f.Source.Port()) == result.LocalPorts[0] && f.Destination == netip.AddrPortFrom(dst, wire.PortUDPEcho) {
			flow, matched = f, matched+1
		}
	}
	line, known, err := loadFlowLine(flow, AppPath(name), bg.Pid(), want)
	e.T.Check(matched == 1 && err == nil, "%s: one live UDP flow with a correct identified or unknown route (%d matches, %v)", label, matched, err)
	records := Select(e.Records(), Tagged("udp", result.Token))
	e.T.Check(result.Received == result.Sent && result.Sent == count && Lines(result.Seen)[line] == count && len(records) == count && RecordLines(records)[line] == count,
		"%s: all %d datagrams answered on required line %s, also observed by the server (%d sent, %d answered, %s)", label, count, line, result.Sent, result.Received, Describe(RecordLines(records)))
	e.T.ReleaseCheck(known, "%s: UDP owner is identified (%t); original all-on-%s check would pass: %t", label, known, want, result.Received == count && Lines(result.Seen)[want] == count)
	release.Open(e)
	var final app.UDPResult
	bg.WaitJSON(e, time.Minute, &final)
	e.T.Check(final.Sent == result.Sent && final.Received == result.Received, "%s: observing ownership did not send or discard another attempt", label)
	return final
}

func (e *Env) observeLoadStream(name string, bg *Bg, port uint16) {
	f, present := e.WaitFlow(3*time.Second, func(f engine.Flow) bool {
		return f.Protocol == "tcp" && f.Source.Port() == port && f.Destination.Port() == wire.PortStream && f.Down > 0
	})
	e.T.Require(present && bg.Running(), "%s's stream is live with answers flowing before the load", name)
	_, known, err := loadFlowLine(f, AppPath(name), bg.Pid(), e.loadLine(name))
	e.T.Check(err == nil, "%s's stream has a correct identified or unknown route (%v)", name, err)
	e.T.Check(known, "%s's stream owner is identified before load (%t)", name, known)
	if e.streamFlows == nil {
		e.streamFlows = map[string]engine.Flow{}
	}
	e.streamFlows[f.Source.String()] = f
}

func (e *Env) streamLine(s Stream, want engine.LineID) engine.LineID {
	if !e.deferAttribution {
		return want
	}
	f, ok := e.streamFlows[s.LocalAddr]
	e.T.Check(ok, "the stream result matches its previously inspected live tuple (%s)", s.LocalAddr)
	if ok && f.App == "" {
		return "a"
	}
	return want
}
