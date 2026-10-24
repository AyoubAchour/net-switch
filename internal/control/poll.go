package control

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/control/engine"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
	"github.com/AyoubAchour/net-switch/internal/linehealth"
	"github.com/AyoubAchour/net-switch/internal/lines"
	"github.com/AyoubAchour/net-switch/internal/updates"
	"github.com/AyoubAchour/net-switch/internal/usage"
)

func (c *Core) Poll(ctx context.Context) error {
	s := c.op.Engine.Snapshot()
	c.mu.Lock()
	c.pollSequence++
	c.statusLocked(s)
	c.syncLanesLocked()
	now := c.now()
	items := c.itemsLocked()
	c.sampleLinesLocked(s)
	c.usage.Ingest(items, func(l lines.Line) *usage.Counter {
		m, ok := c.meters[l.Alias]
		if !ok || now-m.at > 5000 {
			return nil
		}
		return &m.counter
	}, func(l lines.Line) *float64 {
		m := c.meters[l.Alias]
		if m.rate == nil || now-m.at > 5000 {
			return nil
		}
		return &m.rate.Down
	}, now)
	next := c.usage.Exhausted(items, now)
	for _, l := range items {
		if next[l.ID] && !c.exhausted[l.ID] {
			c.noteLocked("exhausted", l.ID, l.Label+" has used its data cap. Its apps use other lines until the cap resets.")
			c.closePending[l.ID] = true
			c.log("%s reached its data cap", l.Label)
		} else if !next[l.ID] && c.exhausted[l.ID] {
			c.noteLocked("cap-reset", l.ID, l.Label+" can be used again: its data cap has reset.")
			delete(c.closePending, l.ID)
			c.log("%s's data cap reset", l.Label)
		}
	}
	c.exhausted = next
	if now-c.outsideAt > 5000 {
		c.outside.Reset()
	}
	gen := c.generation
	c.mu.Unlock()
	if s.Status != "on" {
		return nil
	}
	// Routing decisions never wait for the statistics endpoint. Closure intents
	// carry the acknowledged apply point, so reads after it cannot close new flows.
	policyErr := c.laneQueue.Do(ctx, func() error { return c.closeExhausted(ctx, nil, gen) })
	if policyErr != nil {
		c.log("could not apply routing policy or finish closures: %v", policyErr)
	}
	connections, err := c.op.Engine.Connections(ctx)
	if err != nil {
		c.mu.Lock()
		if gen == c.generation {
			c.monitorFailures++
			if c.monitorFailures == 3 {
				c.tracker.Reset()
				c.log("speed readings stopped: the engine is not answering")
			}
		}
		c.mu.Unlock()
		c.scheduleProbes(ctx, nil)
		return nil
	}
	c.mu.Lock()
	if gen != c.generation {
		c.mu.Unlock()
		return nil
	}
	c.monitorFailures = 0
	c.connections = map[string]int{}
	routed := []apps.Connection{}
	for _, v := range connections {
		routed = append(routed, v.Connection)
		if line := apps.ConnectionLine(&v.Connection); line != nil {
			c.connections[*line]++
		}
	}
	c.tracker.Ingest(routed, now)
	c.mu.Unlock()
	paths := []string{}
	for _, connection := range connections {
		if connection.Metadata.ProcessPath != "" {
			paths = append(paths, connection.Metadata.ProcessPath)
		}
	}
	c.lookupInfo(paths)
	if err := c.laneQueue.Do(ctx, func() error { return c.finishClosures(ctx, gen) }); err != nil {
		c.log("could not finish closure intents: %v", err)
	}
	c.scheduleProbes(ctx, connections)
	c.scheduleTotals(ctx, gen)
	return nil
}

func (c *Core) sampleLinesLocked(s engine.Snapshot) {
	c.initialSampled = true
	now := c.now()
	items := c.itemsLocked()
	for _, item := range items {
		l := c.lanes[item.ID]
		l.sampled = true
		address := false
		route := false
		for _, a := range c.adapters {
			if a["alias"] != item.Alias {
				continue
			}
			ips := array(a["ipv4s"])
			address = len(ips) > 0
			for _, ip := range ips {
				for _, r := range c.routes {
					if ip == r["interfaceAddress"] {
						route = true
					}
				}
			}
		}
		before := l.health.Up
		recoveredBefore := l.health.RecoveredAt
		up := l.health.Check(address, now, c.canTestLocked(item.ID, s))
		if recoveredBefore != l.health.RecoveredAt {
			l.probeAt = nil
			l.routeReadAt = nil
			delete(c.evidence, item.ID)
		}
		// Node samples health before its background route read completes. Count
		// each native snapshot once, with the same five-second read spacing.
		if address && now-c.routesAt <= 30000 &&
			c.routesSequence > l.routeSequence &&
			(l.routeReadAt == nil || now < *l.routeReadAt || now-*l.routeReadAt >= linehealth.RouteReadEveryMS) {
			l.health.NoteRoute(ptr(route), c.routesAt)
			l.routeReadAt = ptr(now)
			l.routeSequence = c.routesSequence
		}
		if before != nil && up != nil && *before != *up {
			if *up {
				c.log("%s is up again", item.Label)
				c.noteLocked("up", item.ID, item.Label+" is back.")
			} else {
				c.log("%s is down (%s)", item.Label, *l.health.Reason)
				reason := "it doesn’t work right now"
				if l.health.Reason != nil {
					switch *l.health.Reason {
					case "no address":
						reason = "it isn’t connected"
					case "no default route":
						reason = "Windows has no internet route through it"
					case "no internet":
						reason = "it doesn’t reach the internet"
					}
				}
				c.noteLocked("down", item.ID, item.Label+" is down: "+reason+".")
			}
		}
	}
}
func (c *Core) closeExhausted(ctx context.Context, connections []engine.Connection, gen uint64) error {
	pending, err := c.pendingClosures()
	if err != nil {
		return err
	}
	c.mu.Lock()
	if gen != c.generation {
		c.mu.Unlock()
		return nil
	}
	s := c.op.Engine.Snapshot()
	p := c.policyLocked()
	if !p.Combine {
		p.Shares = append(lines.Shares{}, s.Policy.Shares...)
	}
	intents := append([]closureIntent{}, pending...)
	for _, line := range c.itemsLocked() {
		if !c.closePending[line.ID] {
			continue
		}
		if closureNeeded(p, line.ID) {
			period := float64(0)
			if used := c.usage.Used(line.ID); used != nil {
				period = used.PeriodStart
			}
			existing := false
			for _, intent := range pending {
				if intent.Request.Line == line.ID && intent.Request.Instance == s.Instance && intent.PeriodStart == period {
					existing = true
					break
				}
			}
			if existing {
				continue
			}
			var ids []string
			if connections != nil {
				ids = []string{}
			}
			for _, v := range connections {
				if id := apps.ConnectionLine(&v.Connection); id != nil && *id == line.ID {
					ids = append(ids, v.ID)
				}
			}
			id := c.op.ID()
			intents = append(intents, closureIntent{ID: id, PeriodStart: period, Request: engine.CloseRequest{OperationID: id, Line: line.ID, Instance: s.Instance, ConnectionIDs: ids}})
		} else if len(p.Lines) < 2 || p.Lines[0].ID == line.ID {
			delete(c.closePending, line.ID)
		}
	}
	c.mu.Unlock()
	if len(intents) == 0 {
		return c.applyPolicy(ctx, true)
	}
	return c.applyWithClosures(ctx, p, intents, gen)
}

var defaultTargets = []string{"1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"}

// acceptProbe applies the two checks every probe result must pass before it
// may change a line's state. A quick result can never stand in for the full
// HTTPS check that brings a line back (spec §4.5), and a result from an engine
// instance that is no longer current says nothing about the current one. A
// rejected result becomes engineUnavailable, which changes nothing.
func acceptProbe(r engine.ProbeResult, quick bool, asked, current string) engine.ProbeResult {
	want := "full"
	if quick {
		want = "quick"
	}
	if r.Outcome == engine.Unavailable {
		return r
	}
	if r.Kind != want || r.Instance != asked || asked != current {
		return engine.ProbeResult{Outcome: engine.Unavailable, Kind: r.Kind, Instance: r.Instance}
	}
	return r
}

func customTargets(v any, explicit bool) bool {
	list := array(v)
	return explicit || (len(list) > 0 && !(len(list) == 2 && list[0] == defaultTargets[0] && list[1] == defaultTargets[1]))
}

func probeTargets(v any, custom bool) []string {
	out := []string{}
	for _, x := range array(v) {
		out = append(out, js.Text(x))
	}
	if custom && len(out) > 0 {
		return out
	}
	// The inherited default pair denotes the product defaults. A custom list
	// replaces all operators, rather than being silently appended to them.
	if len(out) == 0 || (len(out) == 2 && out[0] == defaultTargets[0] && out[1] == defaultTargets[1]) {
		return append([]string{}, defaultTargets...)
	}
	return out
}
func (c *Core) scheduleProbes(ctx context.Context, conns []engine.Connection) {
	c.mu.Lock()
	s := c.op.Engine.Snapshot()
	if s.Status != "on" || s.StartedWith == nil || len(s.StartedWith.Lines) < 2 {
		c.mu.Unlock()
		return
	}
	now := c.now()
	for id, hosts := range c.evidence {
		for host, at := range hosts {
			if now-at > 30000 {
				delete(hosts, host)
			}
		}
		if len(hosts) == 0 {
			delete(c.evidence, id)
		}
	}
	for _, conn := range conns {
		line := apps.ConnectionLine(&conn.Connection)
		if line == nil || conn.Download <= 0 || conn.Host == "" {
			continue
		}
		start, err := time.Parse(time.RFC3339Nano, conn.Start)
		if err != nil || now-start.UnixMilli() < 0 || now-start.UnixMilli() > 30000 {
			continue
		}
		if l := c.lanes[*line]; l != nil && l.health.RecoveredAt != nil && start.UnixMilli() < *l.health.RecoveredAt {
			continue
		}
		if c.evidence[*line] == nil {
			c.evidence[*line] = map[string]int64{}
		}
		c.evidence[*line][strings.ToLower(strings.TrimSuffix(conn.Host, "."))] = start.UnixMilli()
	}
	type probeJob struct {
		line string
		run  func()
	}
	jobs := []probeJob{}
	for _, item := range c.itemsLocked() {
		l := c.lanes[item.ID]
		if l.probing || !c.canTestLocked(item.ID, s) || l.health.HadAddress == nil || !*l.health.HadAddress {
			continue
		}
		doubt := l.health.InDoubt()
		wait := int64(15000)
		if doubt {
			wait = 5000
		}
		if l.probeAt != nil && now-*l.probeAt < wait {
			continue
		}
		l.probeAt = ptr(now)
		l.probing = true
		generation := l.generation
		id := item.ID
		index := uint32(0)
		for _, a := range c.adapters {
			if a["alias"] == item.Alias {
				index = uint32(js.Number(a["index"]))
			}
		}
		realPassed := len(c.evidence[id]) >= 2 && l.health.Up != nil && *l.health.Up && !l.health.Offline && !l.health.AwaitingPass
		targets := probeTargets(c.values["probeTargets"], c.values["probeTargetsCustom"] == true)
		custom := customTargets(c.values["probeTargets"], c.values["probeTargetsCustom"] == true)
		operator := l.operator % len(targets)
		l.operator = (operator + 1) % len(targets)
		instance := s.Instance
		jobs = append(jobs, probeJob{id, func() {
			result := engine.ProbeResult{Outcome: engine.Unavailable}
			probe := func(target string, quick bool) engine.ProbeResult {
				answer := c.op.Engine.Probe(ctx, engine.ProbeRequest{OperationID: c.op.ID(), Line: id, Index: index, Target: target, Quick: quick, Custom: custom})
				return acceptProbe(answer, quick, instance, c.op.Engine.Snapshot().Instance)
			}
			if realPassed {
				result.Outcome = engine.OK
			} else {
				if !doubt {
					result = probe(targets[operator], true)
				}
				if doubt || result.Outcome != engine.OK {
					fullStart := operator
					if !doubt {
						fullStart = (operator + 1) % len(targets)
					}
					results := make([]engine.ProbeResult, min(2, len(targets)))
					var checks sync.WaitGroup
					for i := range results {
						checks.Add(1)
						go func() {
							defer checks.Done()
							defer c.op.Crash.Recover("line probe")
							results[i] = probe(targets[(fullStart+i)%len(targets)], false)
						}()
					}
					checks.Wait()
					result = engine.ProbeResult{Outcome: engine.LineFailed}
					unavailable := false
					for _, answer := range results {
						if answer.Outcome == engine.Unavailable {
							unavailable = true
						}
						if answer.Outcome == engine.OK && result.Outcome != engine.OK {
							result = answer
						}
					}
					if result.Outcome != engine.OK && unavailable {
						result.Outcome = engine.Unavailable
					}
				}
			}
			c.mu.Lock()
			defer c.mu.Unlock()
			current := c.lanes[id]
			if current != l || l.generation != generation {
				return
			}
			l.probing = false
			if result.Outcome == engine.Unavailable {
				return
			}
			if result.Delay != nil {
				l.delay = ptr(math.Round(*result.Delay))
			} else if !realPassed {
				l.delay = nil
			}
			if result.Outcome == engine.LineFailed {
				rate := c.tracker.LineRate(id)
				if rate.Down >= 16*1024 || rate.Up >= 16*1024 {
					c.laneLogLocked(l, "probe-busy", fmt.Sprintf("%s didn't answer an internet test in time, but it is carrying traffic, so it still counts as working", c.labelLocked(id)))
					return
				}
				if !l.health.Offline {
					c.laneLogLocked(l, "probe", fmt.Sprintf("%s didn't reach the internet in a test", c.labelLocked(id)))
				}
				// Parallel operator checks confirm one round, not three votes.
				l.health.NoteProbe(ptr(false), now)
			} else {
				l.health.NoteProbe(ptr(true), now)
			}
		}})
	}
	c.mu.Unlock()
	for _, job := range jobs {
		run := func() { defer c.op.Crash.Recover("line probe"); job.run() }
		if c.op.ProbeBackground != nil {
			c.op.ProbeBackground(job.line, run)
		} else {
			c.op.Background(run)
		}
	}
}

func (c *Core) canTestLocked(id string, s engine.Snapshot) bool {
	if s.Status != "on" || s.StartedWith == nil || len(s.StartedWith.Lines) < 2 || c.exhausted[id] {
		return false
	}
	for _, line := range s.StartedWith.Lines {
		if line.ID == id {
			return true
		}
	}
	return false
}

func (c *Core) laneLogLocked(l *lane, key, text string) {
	if l.logged == nil {
		l.logged = map[string]int64{}
	}
	if at, ok := l.logged[key]; ok && c.now()-at < 30000 {
		return
	}
	l.logged[key] = c.now()
	c.log("%s", text)
}

// Run schedules polls after their previous completion, so a slow read never
// creates an unbounded queue. Workers have independent deadlines and generations.
func (c *Core) Run() {
	every := func(period time.Duration, run func(context.Context) error) {
		c.op.Background(func() {
			for {
				if err := run(c.ctx); err != nil {
					c.log("background operation failed: %v", err)
				}
				select {
				case <-c.ctx.Done():
					return
				case <-c.op.Clock.After(period):
				}
			}
		})
	}
	every(time.Second, c.Poll)
	every(time.Second, c.Supervise)
	c.op.Background(func() {
		c.op.Platform.Stream(c.ctx, "network", func(b []byte) {
			v, err := js.Decode(b)
			if err != nil {
				c.log("network worker returned invalid JSON: %v", err)
				return
			}
			c.mu.Lock()
			gen := c.generation
			c.mu.Unlock()
			if err := c.ApplyNetwork(c.ctx, js.Object(v), gen, c.networkIssued.Add(1)); err != nil {
				c.log("adapter scan failed: %v", err)
			}
		}, func(err error) { c.log("network worker: %v; keeping last good adapter list", err) })
	})
	every(time.Minute, func(context.Context) error { return c.SaveUsage() })
	for _, mode := range []string{"meters", "outside"} {
		if mode == "outside" && c.op.Mode == "proxy" {
			continue
		}
		mode := mode
		c.op.Background(func() {
			c.op.Platform.Stream(c.ctx, mode, func(b []byte) { c.HelperLine(b) }, func(err error) { c.log("%s worker: %v", mode, err) })
		})
	}
	c.op.Background(func() {
		select {
		case <-c.ctx.Done():
			return
		case <-c.op.Clock.After(time.Minute):
		}
		for {
			_, err := c.CheckUpdate(c.ctx, false)
			if err != nil {
				c.log("update check: %v", err)
			}
			select {
			case <-c.ctx.Done():
				return
			case <-c.op.Clock.After(12 * time.Hour):
			}
		}
	})
}
func (c *Core) CheckUpdate(ctx context.Context, force bool) (string, error) {
	c.mu.Lock()
	call := c.updateCheck
	if call == nil {
		enabled := c.op.Mode != "proxy" && (force || c.values["checkForUpdates"] == true)
		if !enabled {
			c.mu.Unlock()
			return "off", nil
		}
		call = &updateCall{done: make(chan struct{})}
		c.updateCheck = call
		c.mu.Unlock()
		// The shared check belongs to Control, not to the first HTTP client's
		// connection. Its checker supplies the same 15-second deadline as Node.
		call.result = c.checkUpdateNow(c.ctx)
		c.mu.Lock()
		c.updateCheck = nil
		close(call.done)
		c.mu.Unlock()
	} else {
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return "failed", ctx.Err()
		case <-call.done:
		}
	}
	c.mu.Lock()
	skipped := call.result == "available" && c.offer != nil && c.values["skippedUpdate"] == c.offer.Version
	c.mu.Unlock()
	if force && skipped {
		if err := c.save(map[string]any{"skippedUpdate": nil}); err != nil {
			return "failed", err
		}
	}
	return call.result, nil
}

type updateCall struct {
	done   chan struct{}
	result string
}

func (c *Core) checkUpdateNow(ctx context.Context) string {
	var offer *updates.Offer
	var err error
	if c.op.CheckUpdate == nil {
		err = fmt.Errorf("update checker not configured")
	} else {
		offer, err = c.op.CheckUpdate(ctx)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		reason := err.Error()
		if errors.Is(err, context.DeadlineExceeded) {
			reason = "no answer within 15 seconds"
		}
		if reason != c.lastUpdateFailure {
			c.log("could not check for updates: %s", reason)
		}
		c.lastUpdateFailure = reason
		return "failed"
	}
	if offer != nil && (c.offer == nil || c.offer.Version != offer.Version) {
		c.log("Net Switch %s is available (this is %s)", offer.Version, c.op.Version)
	}
	c.offer = offer
	c.lastUpdateFailure = ""
	if offer != nil {
		return "available"
	}
	return "latest"
}
