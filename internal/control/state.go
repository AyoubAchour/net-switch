package control

import (
	"encoding/json"
	"strings"

	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/control/engine"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
	"github.com/AyoubAchour/net-switch/internal/lines"
)

// Keep the API's nested numeric records in the JSON sanitizer's object form.
// encoding/json rejects NaN in a struct before it can emit the required null.
func rateJSON(rate *apps.Rate) any {
	if rate == nil {
		return nil
	}
	return map[string]any{"down": rate.Down, "up": rate.Up}
}
func outsideJSON(row *apps.OutsideRow) any {
	if row == nil {
		return nil
	}
	return map[string]any{"connections": row.Connections, "byLine": row.ByLine, "beforeRouting": row.BeforeRouting, "measured": row.Measured, "rate": rateJSON(row.Rate)}
}

func (c *Core) combineActiveLocked(s engine.Snapshot) bool {
	if !s.Policy.Combine || s.Status != "on" {
		return false
	}
	n := 0
	for _, share := range s.Policy.Shares {
		if share.Value > 0 && c.targetLocked(share.ID, s) == share.ID {
			n++
		}
	}
	return n >= 2
}
func (c *Core) targetLocked(id string, s engine.Snapshot) string {
	if s.StartedWith == nil || len(s.StartedWith.Lines) < 2 {
		return id
	}
	if l := c.lanes[id]; l != nil && l.target != nil {
		return *l.target
	}
	return id
}
func metric(a map[string]any) float64 {
	m := 9999.0
	if a["metric"] != nil {
		m = js.Number(a["metric"])
	}
	if a["routeMetric"] != nil {
		m += js.Number(a["routeMetric"])
	}
	return m
}
func (c *Core) outrankingLocked() (map[string]any, []map[string]any) {
	var main map[string]any
	others := []map[string]any{}
	items := c.itemsLocked()
	if len(items) == 0 {
		return main, others
	}
	for _, a := range c.adapters {
		if a["alias"] == items[0].Alias && a["connected"] == true {
			main = a
			break
		}
	}
	if main == nil {
		return main, others
	}
	for _, l := range items[1:] {
		for _, a := range c.adapters {
			if a["alias"] == l.Alias && a["alias"] != main["alias"] && a["connected"] == true && metric(a) <= metric(main) {
				others = append(others, a)
			}
		}
	}
	return main, others
}
func baseName(path string) string {
	path = strings.ReplaceAll(path, "/", `\`)
	parts := strings.Split(path, `\`)
	name := parts[len(parts)-1]
	if strings.HasSuffix(strings.ToLower(name), ".exe") {
		name = name[:len(name)-4]
	}
	return name
}
func (c *Core) describeLocked(path string) map[string]any {
	key := apps.AppKey(path)
	name := baseName(path)
	switchable, reconnectable := true, true
	if key == "unknown" {
		name = "Unknown app"
		switchable = false
		reconnectable = false
	} else if key == `c:\windows\system32\svchost.exe` {
		name = "Windows services"
		reconnectable = false
	}
	info := c.info[key]
	c.queueInfoLocked([]string{path})
	if v := js.Text(info["name"]); v != "" && key != `c:\windows\system32\svchost.exe` {
		name = v
	}
	return map[string]any{"name": name, "hasIcon": js.Truth(info["icon"]), "switchable": switchable, "reconnectable": reconnectable}
}

// State emits every legacy field, including explicit nulls. It takes one state
// lock so a response cannot mix policy generations.
func (c *Core) State() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.op.Engine.Snapshot()
	for _, line := range c.itemsLocked() {
		if lane := c.lanes[line.ID]; lane != nil && lane.health.Up == nil {
			c.sampleLinesLocked(s)
			break
		}
	}
	items := c.itemsLocked()
	routing := s.Status == "on"
	ll := []any{}
	candidates := []any{}
	appRows := []any{}
	wifi := false
	hasWifiLine := false
	for i, line := range items {
		var adapter map[string]any
		for _, a := range c.adapters {
			if a["alias"] == line.Alias {
				adapter = a
				break
			}
		}
		kind := any(line.Kind)
		if line.Kind == nil {
			kind = adapter["kind"]
		}
		if (line.Kind != nil && *line.Kind == "wifi") || adapter["kind"] == "wifi" {
			hasWifiLine = true
		}
		l := c.lanes[line.ID]
		connected := l != nil && l.health.Up != nil && *l.health.Up
		var problem any
		var ping any
		if l != nil {
			if l.health.Up != nil && !*l.health.Up {
				problem = l.health.Reason
			}
			if connected {
				ping = l.delay
			}
		}
		var target any
		carrying := false
		if routing {
			t := c.targetLocked(line.ID, s)
			target = t
			carrying = t == line.ID
		}
		var rate any
		if m, ok := c.meters[line.Alias]; ok && c.now()-m.at <= 5000 {
			rate = rateJSON(m.rate)
		}
		ssid := adapter["ssid"]
		if !js.Truth(ssid) {
			ssid = nil
		}
		blocked := false
		for _, id := range s.Policy.Blocked {
			blocked = blocked || id == line.ID
		}
		var share any
		if s.Policy.Combine {
			share = float64(0)
			for _, v := range s.Policy.Shares {
				if v.ID == line.ID {
					share = v.Value
				}
			}
		}
		ll = append(ll, map[string]any{
			"id": line.ID, "alias": line.Alias, "label": json.RawMessage(js.MarshalString(line.Label)),
			"kind": kind, "main": i == 0, "connected": connected, "problem": problem, "ping": ping,
			"connections": c.connections[line.ID], "carrying": carrying, "target": target,
			"rate": rate, "ssid": ssid, "metered": line.Metered, "strict": line.Strict,
			"cap": line.Cap, "usage": c.usage.Used(line.ID), "exhausted": c.exhausted[line.ID],
			"blocked": blocked, "weight": line.Weight, "share": share,
		})
	}
	for _, a := range c.adapters {
		if a["kind"] == "wifi" {
			wifi = true
		}
		taken := false
		for _, l := range items {
			taken = taken || l.Alias == a["alias"]
		}
		if a["connected"] == true && !taken {
			ssid := a["ssid"]
			if !js.Truth(ssid) {
				ssid = nil
			}
			candidates = append(candidates, map[string]any{"alias": a["alias"], "label": lines.LineLabel(a), "kind": a["kind"], "ssid": ssid})
		}
	}
	for _, a := range apps.MergeRows(c.tracker.Snapshot(c.pinsLocked()), c.outside, c.pinsLocked()) {
		row := c.describeLocked(a.Path)
		row["key"] = a.Key
		row["path"] = a.Path
		row["line"] = a.Line
		row["rate"] = rateJSON(&a.Rate)
		row["lineDown"] = a.LineDown
		row["sortScore"] = a.SortScore
		row["connections"] = a.Connections
		row["outside"] = outsideJSON(a.Outside)
		// Only Linux sandbox apps have an identity apart from their path; a
		// path pin that cannot match such an app is kept but flagged, never
		// routed by guess. Windows rows and 0.3.x shapes are unchanged.
		if a.Identity != "" {
			row["identity"] = a.Identity
		}
		if a.Line != nil {
			for _, p := range c.pinsLocked() {
				if apps.AppKey(p.Path) == a.Key && apps.PinNeedsReselection(p, a.Identity) {
					row["pinNeedsReselection"] = true
				}
			}
		}
		appRows = append(appRows, row)
	}
	var retryAt, ipv6, offer, autostart any
	if routing {
		ipv6 = s.StartedWith != nil && s.StartedWith.IPv6
	}
	if c.wanted && s.Status == "error" && (c.op.Mode != "tun" || c.elevated) && (!c.op.ServiceMode || len(c.failureTimes) < 5) {
		retryAt = c.retryAt
	}
	if c.offer != nil && c.values["skippedUpdate"] != c.offer.Version {
		offer = c.offer
	}
	if c.op.AutostartAllowed {
		autostart = c.autostart
	}
	undo := map[string]any{}
	if c.op.Undo != nil {
		undo = c.op.Undo.Values()
	}
	metricChanged := false
	for _, v := range js.Object(undo["metrics"]) {
		metricChanged = metricChanged || len(array(v)) > 0
	}
	_, policyChanged := js.Object(undo["policy"])["value"]
	_, others := c.outrankingLocked()
	updates := c.op.Mode != "proxy" && c.values["checkForUpdates"] == true
	return map[string]any{
		"mode": c.op.Mode, "elevated": c.elevated, "version": c.op.Version,
		"update": offer, "updateChecks": updates,
		"features": map[string]any{"reconnect": true, "combine": true, "lines": true, "installedApps": true},
		"combine":  map[string]any{"on": s.Policy.Combine, "active": c.combineActiveLocked(s), "mode": c.values["combineMode"]},
		"routing": map[string]any{
			"status": s.Status, "wanted": c.wanted, "error": s.Error,
			"measuring": routing && c.monitorFailures < 3,
			"proxyPort": s.ProxyPort, "ipv6": ipv6, "retryAt": retryAt,
		},
		"lines": ll, "candidates": candidates, "apps": appRows,
		"events": append([]map[string]any{}, c.events...),
		"settings": map[string]any{
			"autostart": autostart, "checkForUpdates": updates,
			"probeTargets": probeTargets(c.values["probeTargets"], c.values["probeTargetsCustom"] == true),
		},
		"setup": map[string]any{
			"cableNotDefault": len(others) > 0, "wifiBlocked": c.policy == float64(3) && wifi,
			"keepBothConnected": len(items) > 1 && hasWifiLine && c.policy != float64(0) && c.policy != float64(3),
			"changed":           map[string]any{"cableDefault": metricChanged, "keepBoth": policyChanged},
		},
	}
}
