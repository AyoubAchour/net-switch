package control

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/engine"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
	"github.com/AyoubAchour/net-switch/internal/lines"
	"github.com/AyoubAchour/net-switch/internal/usage"
)

func (c *Core) Poll(ctx context.Context) error {
	s := c.op.Engine.Snapshot()
	c.mu.Lock()
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
	// Capture the set before applying the policy. A retry can only close these
	// identities; a flow admitted after acknowledgement must never be swept up.
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
		return err
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
	if err := c.laneQueue.Do(ctx, func() error { return c.closeExhausted(ctx, connections, gen) }); err != nil {
		return err
	}
	c.scheduleProbes(ctx, connections)
	return nil
}

func (c *Core) sampleLinesLocked(s engine.Snapshot) {
	now := c.now()
	items := c.itemsLocked()
	for _, item := range items {
		l := c.lanes[item.ID]
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
		if address && now-c.routesAt <= 30000 {
			l.health.NoteRoute(ptr(route), now)
		}
		before := l.health.Up
		recoveredBefore := l.health.RecoveredAt
		up := l.health.Check(address, now, s.Status == "on" && len(items) > 1)
		if recoveredBefore != l.health.RecoveredAt {
			l.probeAt = nil
		}
		if before != nil && up != nil && *before != *up {
			if *up {
				c.noteLocked("up", item.ID, item.Label+" is back.")
			} else {
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
	c.mu.Lock()
	if gen != c.generation {
		c.mu.Unlock()
		return nil
	}
	s := c.op.Engine.Snapshot()
	p := c.policyLocked()
	intents := []closureIntent{}
	for _, line := range c.itemsLocked() {
		if !c.closePending[line.ID] {
			continue
		}
		moved := p.Lanes[line.ID] != "" && p.Lanes[line.ID] != line.ID
		blocked := false
		for _, id := range p.Blocked {
			blocked = blocked || id == line.ID
		}
		if moved || blocked {
			ids := []string{}
			for _, v := range connections {
				if id := apps.ConnectionLine(&v.Connection); id != nil && *id == line.ID {
					ids = append(ids, v.ID)
				}
			}
			id := c.op.ID()
			intents = append(intents, closureIntent{ID: id, Request: engine.CloseRequest{OperationID: id, Line: line.ID, Instance: s.Instance, StartedBefore: c.op.Clock.Now(), ConnectionIDs: ids}})
		} else if len(p.Lines) < 2 || p.Lines[0].ID == line.ID {
			delete(c.closePending, line.ID)
		}
	}
	c.mu.Unlock()
	if len(intents) == 0 {
		return c.ApplyPolicy(ctx)
	}
	return c.applyWithClosures(ctx, p, intents, gen)
}

var defaultTargets = []string{"1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"}

func probeTargets(v any) []string {
	out := []string{}
	for _, x := range array(v) {
		out = append(out, js.Text(x))
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
	jobs := []func(){}
	for _, item := range c.itemsLocked() {
		l := c.lanes[item.ID]
		if l.probing || c.exhausted[item.ID] || l.health.HadAddress == nil || !*l.health.HadAddress {
			continue
		}
		doubt := l.health.InDoubt() || l.health.Up == nil || !*l.health.Up
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
		hosts := map[string]bool{}
		for _, conn := range conns {
			if line := apps.ConnectionLine(&conn.Connection); line != nil && *line == id && conn.Download > 0 && conn.Host != "" {
				start, err := time.Parse(time.RFC3339Nano, conn.Start)
				if err == nil && now-start.UnixMilli() >= 0 && now-start.UnixMilli() <= 30000 {
					hosts[conn.Host] = true
				}
			}
		}
		realPassed := len(hosts) >= 2
		targets := probeTargets(c.values["probeTargets"])
		operator := l.operator % len(targets)
		l.operator = (operator + 1) % len(targets)
		jobs = append(jobs, func() {
			result := engine.ProbeResult{Outcome: engine.Unavailable}
			failedChecks := 0
			probe := func(target string, quick bool) engine.ProbeResult {
				return c.op.Engine.Probe(ctx, engine.ProbeRequest{OperationID: c.op.ID(), Line: id, Index: index, Target: target, Quick: quick})
			}
			if realPassed {
				result.Outcome = engine.OK
			} else {
				if !doubt {
					result = probe(targets[operator], true)
				}
				if doubt || result.Outcome != engine.OK {
					// A quick failure is the first vote; two distinct full operator
					// checks supply the remaining votes in today's health machine.
					if result.Outcome == engine.LineFailed {
						failedChecks++
					}
					result = probe(targets[operator], false)
					if result.Outcome == engine.LineFailed {
						failedChecks++
						if len(targets) > 1 {
							other := probe(targets[(operator+1)%len(targets)], false)
							if other.Outcome == engine.LineFailed {
								failedChecks++
							}
							result = other
						}
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
			} else {
				l.delay = nil
			}
			if result.Outcome == engine.LineFailed {
				rate := c.tracker.LineRate(id)
				if rate.Down >= 16*1024 || rate.Up >= 16*1024 {
					c.log("%s didn't answer an internet test in time, but it is carrying traffic", c.labelLocked(id))
					return
				}
				for i := 0; i < max(1, failedChecks); i++ {
					l.health.NoteProbe(ptr(false), now)
				}
			} else {
				l.health.NoteProbe(ptr(true), now)
			}
		})
	}
	c.mu.Unlock()
	for _, job := range jobs {
		c.op.Background(job)
	}
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
			if err := c.ApplyNetwork(c.ctx, js.Object(v), gen); err != nil {
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
	enabled := c.op.Mode != "proxy" && (force || c.values["checkForUpdates"] == true)
	c.mu.Unlock()
	if !enabled {
		return "off", nil
	}
	if c.op.CheckUpdate == nil {
		return "failed", fmt.Errorf("update checker not configured")
	}
	offer, err := c.op.CheckUpdate(ctx)
	if err != nil {
		return "failed", err
	}
	c.mu.Lock()
	c.offer = offer
	skipped := offer != nil && c.values["skippedUpdate"] == offer.Version
	c.mu.Unlock()
	if force && skipped {
		if err := c.save(map[string]any{"skippedUpdate": nil}); err != nil {
			return "failed", err
		}
	}
	if offer != nil {
		return "available", nil
	}
	return "latest", nil
}
