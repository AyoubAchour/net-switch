package control

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
	"unicode/utf16"

	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/control/engine"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
	"github.com/AyoubAchour/net-switch/internal/lines"
	"github.com/AyoubAchour/net-switch/internal/platform"
	"github.com/AyoubAchour/net-switch/internal/windowsundo"
)

func (c *Core) Action(ctx context.Context, method, path string, b map[string]any) (any, error) {
	if method == "GET" {
		switch path {
		case "/api/ping":
			return map[string]any{"ok": true}, nil
		case "/api/state":
			return c.State(), nil
		case "/api/installed-apps":
			return c.InstalledApps(ctx)
		}
	}
	// Once a command is accepted, Node keeps processing it after the browser
	// disconnects. Queues, worker calls and policy applies share that lifetime.
	ctx = c.ctx
	var err error
	switch path {
	case "/api/routing":
		err = c.Routing(ctx, js.Truth(b["on"]))
	case "/api/app-line":
		err = c.laneQueue.Do(ctx, func() error {
			path := js.Text(b["path"])
			id, ok := b["line"].(string)
			if path == "" || (!ok && b["line"] != nil) {
				return bad("Choose an app and a line, then try again.")
			}
			c.mu.Lock()
			exists := id == "" && b["line"] == nil
			for _, l := range c.itemsLocked() {
				exists = exists || l.ID == id
			}
			// A pin stores the identity the person selected. For an app the
			// engine reports under a sandbox identity, that is the identity,
			// never the path other sandboxes may share; a path pin for it is
			// replaced here. On Windows the identity is the path as today.
			identity := path
			if tracked := c.tracker.IdentityOf(apps.AppKey(path)); tracked != "" {
				identity = tracked
			}
			pins := apps.Pins{}
			for _, p := range c.pinsLocked() {
				if apps.AppKey(p.Path) != apps.AppKey(path) && apps.AppKey(p.Path) != apps.AppKey(identity) {
					pins = append(pins, p)
				}
			}
			c.mu.Unlock()
			if !exists {
				return bad("That line isn’t there any more.")
			}
			if b["line"] != nil {
				pins = append(pins, apps.Pin{Path: identity, LineID: id})
			}
			if err := c.save(map[string]any{"appLines": pins}); err != nil {
				return err
			}
			return c.ApplyPolicy(ctx)
		})
	case "/api/combine":
		err = c.laneQueue.Do(ctx, func() error { return c.setCombine(ctx, b) })
	case "/api/lines/add", "/api/lines/remove", "/api/lines/order", "/api/lines/update":
		err = c.laneQueue.Do(ctx, func() error { return c.changeLines(ctx, path, b) })
	case "/api/reconnect":
		var result map[string]any
		err = c.laneQueue.Do(ctx, func() error { var e error; result, e = c.reconnect(ctx, js.Text(b["key"])); return e })
		if err == nil {
			result["state"] = c.State()
			return result, nil
		}
	case "/api/settings":
		err = c.changeSettings(ctx, b)
	case "/api/update/dismiss":
		if js.Text(b["version"]) == "" {
			err = bad("Choose which update to skip, then try again.")
		} else {
			err = c.save(map[string]any{"skippedUpdate": b["version"]})
		}
	case "/api/update/check":
		if c.op.Mode == "proxy" {
			return nil, bad("Test mode doesn’t check for updates.")
		}
		result, e := c.CheckUpdate(ctx, true)
		if e != nil {
			c.log("could not check for updates: %v", e)
		}
		state := c.State()
		var version any
		c.mu.Lock()
		if c.offer != nil {
			version = c.offer.Version
		}
		c.mu.Unlock()
		state["check"] = map[string]any{"result": result, "version": version}
		return state, nil
	case "/api/setup/cable-default", "/api/setup/keep-both", "/api/setup/undo":
		err = c.setupQueue.Do(ctx, func() error { return c.setup(ctx, path) })
	case "/api/quit":
		if err := c.Shutdown(c.ctx); err != nil {
			return nil, bad(err.Error())
		}
		return map[string]any{"ok": true}, nil
	default:
		return nil, routeError(method, path)
	}
	if err != nil {
		return nil, err
	}
	return c.State(), nil
}
func (c *Core) setCombine(ctx context.Context, b map[string]any) error {
	if v, exists := b["on"]; exists {
		if _, ok := v.(bool); !ok {
			return bad("Choose whether to combine the lines, then try again.")
		}
	}
	if v, exists := b["mode"]; exists && v != "auto" && v != "manual" {
		return bad("Choose Auto or Manual, then try again.")
	}
	weights := js.Object(b["weights"])
	if _, exists := b["weights"]; exists && weights == nil {
		return bad("Set how much each line takes, then try again.")
	}
	c.mu.Lock()
	items := c.itemsLocked()
	on := c.values["combine"]
	mode := c.values["combineMode"]
	c.mu.Unlock()
	if v, exists := b["on"]; exists {
		on = v
	}
	if v, exists := b["mode"]; exists {
		mode = v
	}
	for i, l := range items {
		if v, ok := weights[l.ID]; ok {
			n, isNumber := v.(float64)
			if !isNumber || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n > 1000 {
				return bad("Set how much each line takes, then try again.")
			}
			items[i].Weight = n
		}
	}
	if on == true && len(lines.SharingLines(items, nil)) < 2 {
		return bad("Combining needs two lines that any app may use. Add a line, or let one take any app.")
	}
	if err := c.save(map[string]any{"lines": items, "combine": on, "combineMode": mode}); err != nil {
		return err
	}
	return c.ApplyPolicy(ctx)
}
func (c *Core) changeLines(ctx context.Context, action string, b map[string]any) error {
	c.mu.Lock()
	items := c.itemsLocked()
	pins := append(apps.Pins{}, c.pinsLocked()...)
	adapters := c.adapters
	combining := c.values["combine"] == true
	waiting := array(c.values["waitingApps"])
	c.mu.Unlock()
	id := js.Text(b["id"])
	index := -1
	for i, l := range items {
		if l.ID == id {
			index = i
		}
	}
	if action != "/api/lines/add" && action != "/api/lines/order" && index < 0 {
		return bad("That line isn’t there any more.")
	}
	clearWaiting := false
	note := ""
	switch action {
	case "/api/lines/add":
		alias := js.Text(b["alias"])
		var adapter map[string]any
		for _, a := range adapters {
			if a["alias"] == alias && a["connected"] == true {
				adapter = a
				break
			}
		}
		taken := false
		for _, l := range items {
			taken = taken || l.Alias == alias
		}
		if adapter == nil || (taken && c.op.Mode != "proxy") {
			return bad("That connection isn’t available. Check that it’s connected, then try again.")
		}
		if len(items) >= 8 {
			return bad("Net Switch can use up to 8 lines.")
		}
		l := lines.NewLine(adapter, items, c.op.LineID)
		note = fmt.Sprintf("added %s (%s)", l.Label, l.Alias)
		if len(items) > 0 && len(waiting) > 0 {
			pins = lines.PlaceWaitingApps(waiting, pins, l.ID)
			clearWaiting = true
		}
		items = append(items, l)
	case "/api/lines/remove":
		note = fmt.Sprintf("removed %s (%s)", items[index].Label, items[index].Alias)
		if len(items) == 1 {
			return bad("Net Switch needs at least one line.")
		}
		items = append(items[:index], items[index+1:]...)
		next := apps.Pins{}
		for _, p := range pins {
			if p.LineID != id {
				next = append(next, p)
			}
		}
		pins = next
	case "/api/lines/order":
		ids, ok := b["ids"].([]any)
		if !ok || len(ids) != len(items) {
			return bad("The lines changed meanwhile. Try again.")
		}
		seen := map[string]bool{}
		next := []lines.Line{}
		for _, v := range ids {
			key := js.Text(v)
			if seen[key] {
				return bad("The lines changed meanwhile. Try again.")
			}
			found := false
			for _, l := range items {
				if l.ID == key {
					next = append(next, l)
					found = true
				}
			}
			if !found {
				return bad("The lines changed meanwhile. Try again.")
			}
			seen[key] = true
		}
		items = next
		names := make([]string, len(items))
		for i, line := range items {
			names[i] = line.Label
		}
		note = "line order: " + strings.Join(names, ", ")
	case "/api/lines/update":
		next := items[index]
		if v, ok := b["label"]; ok {
			label := js.Trim(js.Text(v))
			if label == "" || len(utf16.Encode([]rune(label))) > 40 {
				return bad("Give the line a name of up to 40 characters.")
			}
			next.Label = label
		}
		if v, exists := b["metered"]; exists {
			val, ok := v.(bool)
			if !ok {
				return bad("Choose whether this line costs data, then try again.")
			}
			next.Metered = val
		}
		if v, exists := b["strict"]; exists {
			val, ok := v.(bool)
			if !ok {
				return bad("Choose which apps may use this line, then try again.")
			}
			if val && index == 0 {
				return bad("The main line carries every app without a line of its own, so it can’t be kept to chosen apps.")
			}
			next.Strict = val
		}
		if v, exists := b["cap"]; exists {
			next.Cap = lines.ValidCap(v)
			if v != nil && next.Cap == nil {
				return bad("Set the data cap as an amount per day or per month, then try again.")
			}
		}
		items[index] = next
	}
	if len(items) > 0 {
		items[0].Strict = false
	}
	combining = combining && len(lines.SharingLines(items, nil)) >= 2
	remove := []string{}
	if clearWaiting {
		remove = append(remove, "waitingApps")
	}
	if err := c.save(map[string]any{"lines": items, "appLines": pins, "combine": combining}, remove...); err != nil {
		return err
	}
	c.mu.Lock()
	c.syncLanesLocked()
	c.mu.Unlock()
	if err := c.ApplyPolicy(ctx); err != nil {
		return err
	}
	if note != "" {
		c.log("%s", note)
	}
	if action != "/api/lines/update" && c.op.Engine.Snapshot().Status != "off" {
		return c.restart(ctx)
	}
	return nil
}
func (c *Core) reconnect(ctx context.Context, key string) (map[string]any, error) {
	if key == "" {
		return nil, bad("Choose an app, then try again.")
	}
	s := c.op.Engine.Snapshot()
	if s.Status != "on" {
		return nil, bad("Turn routing on first.")
	}
	// Resolve any outstanding desired policy before selecting the old flows.
	// Reconnect itself changes no policy; its persisted cutoff is this selection.
	if err := c.ApplyPolicy(ctx); err != nil {
		return nil, err
	}
	s = c.op.Engine.Snapshot()
	c.mu.Lock()
	path := ""
	for _, a := range c.tracker.Snapshot(nil) {
		if a.Key == key {
			path = a.Path
			break
		}
	}
	if path == "" {
		if a := c.outside.Get(key); a != nil {
			path = a.Path
		}
	}
	if c.describeLocked(path)["reconnectable"] != true {
		c.mu.Unlock()
		return nil, bad("This one can’t be reconnected, because other programs share its connections.")
	}
	pinned := ""
	for _, p := range c.pinsLocked() {
		if apps.AppKey(p.Path) == key {
			pinned = p.LineID
		}
	}
	items := c.itemsLocked()
	home := pinned
	if home == "" && len(items) > 0 {
		home = items[0].ID
	}
	target := c.targetLocked(home, s)
	l := c.lanes[target]
	if target == "" || l == nil || l.health.Up == nil || !*l.health.Up {
		label := c.labelLocked(home)
		if label == "" {
			label = "Its line"
		}
		c.mu.Unlock()
		return nil, bad(label + " isn’t connected, so there’s nowhere to move it yet.")
	}
	shared := pinned == "" && c.combineActiveLocked(s)
	routed := []string{}
	outside := c.outside.IDsOf(key)
	if !shared {
		routed = c.tracker.ConnectionIDsOffLine(key, target)
		outside = c.outside.IDsOffLine(key, target)
	}
	tuples := []platform.TCPSelector{}
	for _, id := range outside {
		if t := apps.ParseOutsideID(id); t != nil {
			tuples = append(tuples, platform.TCPSelector{Tuple: *t, ProcessStarted: c.outsideStarts[id]})
		}
	}
	c.mu.Unlock()
	closed, failed, gone := 0, 0, 0
	if len(routed) > 0 {
		// Reconnect selects only the old flows the user saw. Retrying this
		// operation must never select the app's subsequently opened flows.
		intent := closureIntent{ID: c.op.ID(), Revision: s.AppliedRevision, Purpose: "reconnect", Label: key, Request: engine.CloseRequest{Instance: s.Instance, StartedBefore: c.op.Clock.Now(), ConnectionIDs: routed}}
		intent.Request.OperationID = intent.ID
		func() {
			c.applyMu.Lock()
			defer c.applyMu.Unlock()
			if err := c.saveIntent(intent); err != nil {
				failed += len(routed)
				c.log("Reconnect was not sent: %v", err)
				return
			}
			result, err := c.op.Engine.CloseFlows(ctx, intent.Request)
			if err != nil {
				failed += len(routed)
				c.log("could not finish closure: %v", c.retryClosure(intent, err))
				return
			}
			closed += result.Closed
			failed += result.Failed
			gone += result.Gone
			if result.Failed == 0 {
				c.checkpoint("control-after-close-ack")
				if err := c.completeIntent(intent.ID); err != nil {
					c.log("Reconnect completed; its durable acknowledgement is pending: %v", err)
				}
			} else {
				c.log("could not finish closure: %v", c.retryClosure(intent, fmt.Errorf("%d connections could not be closed", result.Failed)))
			}
		}()
	}
	v, err := c.op.Platform.Call(ctx, "close-tcp", map[string]any{"connections": tuples})
	if err != nil {
		return nil, err
	}
	m := js.Object(v)
	closed += int(js.Number(m["closed"]))
	failed += int(js.Number(m["failed"]))
	gone += int(js.Number(m["gone"]))
	codes := []string{}
	for _, code := range array(m["codes"]) {
		codes = append(codes, fmt.Sprint(code))
	}
	c.log("reconnect %s: closed %d, failed %d (codes %s), already gone %d", key, closed, failed, strings.Join(codes, ","), gone)
	return map[string]any{"closed": closed, "failed": failed, "gone": gone}, nil
}
func (c *Core) changeSettings(ctx context.Context, b map[string]any) error {
	for _, key := range []string{"checkForUpdates", "autostart"} {
		if v, exists := b[key]; exists {
			if _, ok := v.(bool); !ok {
				if key == "autostart" {
					return bad("Choose whether Net Switch starts with Windows, then try again.")
				}
				return bad("Choose whether to check for updates, then try again.")
			}
		}
	}
	changes := map[string]any{}
	if v, exists := b["probeTargets"]; exists {
		list, ok := v.([]any)
		valid := ok && len(list) > 0 && len(list) <= 4
		seen := map[string]bool{}
		targets := []string{}
		for _, v := range list {
			text := strings.TrimSpace(js.Text(v))
			addr, err := netip.ParseAddrPort(text)
			if err != nil || !addr.Addr().Is4() || addr.Port() == 0 {
				valid = false
			}
			if !seen[text] {
				targets = append(targets, text)
				seen[text] = true
			}
		}
		if !valid {
			return bad("Enter one to 4 test addresses as address:port, like 1.1.1.1:443.")
		}
		changes["probeTargets"] = targets
		// Preserve an explicit choice even when it equals the inherited Node
		// default pair. Save the marker and list in the same atomic document.
		changes["probeTargetsCustom"] = true
	}
	if on, exists := b["autostart"]; exists {
		if !c.op.AutostartAllowed {
			return bad("Starting with Windows needs Net Switch installed from its installer.")
		}
		if err := c.setupQueue.Do(ctx, func() error { _, err := c.op.Platform.Call(ctx, "autostart-set", map[string]any{"on": on}); return err }); err != nil {
			c.log("could not change starting with Windows to %v: %v", on, err)
			return bad("Windows didn’t accept the change. Try again in a moment.")
		}
		v, err := c.op.Platform.Call(ctx, "autostart", nil)
		if err != nil {
			c.log("could not read whether Net Switch starts with Windows: %v", err)
		} else {
			c.mu.Lock()
			c.autostart = v
			c.mu.Unlock()
		}
		word := "off"
		if on == true {
			word = "on"
		}
		c.log("starting with Windows is %s", word)
	}
	if v, exists := b["checkForUpdates"]; exists {
		changes["checkForUpdates"] = v
	}
	if err := c.save(changes); err != nil {
		return err
	}
	if changes["checkForUpdates"] == true {
		_, err := c.CheckUpdate(ctx, false)
		return err
	}
	if changes["checkForUpdates"] == false {
		c.mu.Lock()
		c.offer = nil
		c.mu.Unlock()
	}
	return nil
}
func (c *Core) setup(ctx context.Context, action string) error {
	if c.op.Undo == nil {
		return fmt.Errorf("Windows undo store not configured")
	}
	undo := c.op.Undo.Values()
	aliases := windowsundo.Aliases(c.op.Undo.RawValues()["metrics"])
	metrics := js.Object(undo["metrics"])
	policy := js.Object(undo["policy"])
	if metrics == nil {
		metrics = map[string]any{}
	}
	if policy == nil {
		policy = map[string]any{}
	}
	switch action {
	case "/api/setup/cable-default":
		c.mu.Lock()
		main, others := c.outrankingLocked()
		c.mu.Unlock()
		if main == nil || len(others) == 0 {
			return bad("Connect the main line and the others, then try again.")
		}
		for _, other := range others {
			alias := js.Text(other["alias"])
			if len(array(metrics[alias])) == 0 {
				before, err := c.op.Platform.Call(ctx, "metrics", map[string]any{"alias": alias})
				if err != nil {
					c.log("could not read %s's settings before changing them: %v", alias, err)
					return bad("Windows didn’t say how this connection is set up now, so Net Switch can’t change it safely. Try again in a moment.")
				}
				metrics[alias] = before
				if !slices.Contains(aliases, alias) {
					aliases = append(aliases, alias)
				}
				if _, err := c.op.Undo.Update(map[string]any{"metrics": windowsundo.MetricsJSON(metrics, aliases)}); err != nil {
					return err
				}
			}
			if _, err := c.op.Platform.Call(ctx, "metrics-set", map[string]any{"alias": alias, "before": metrics[alias], "metric": math.Max(100, metric(main)+50)}); err != nil {
				return err
			}
		}
	case "/api/setup/keep-both":
		if _, ok := policy["value"]; !ok {
			before, err := c.op.Platform.Call(ctx, "policy", nil)
			if err != nil {
				c.log("could not read the Wi-Fi policy before changing it: %v", err)
				return bad("Windows didn’t say how this setting is now, so Net Switch can’t change it safely. Try again in a moment.")
			}
			policy["value"] = before
			if _, err := c.op.Undo.Update(map[string]any{"policy": policy}); err != nil {
				return err
			}
		}
		if _, err := c.op.Platform.Call(ctx, "policy-set", map[string]any{"value": float64(0)}); err != nil {
			return err
		}
		c.refreshPolicy(ctx)
		return nil
	case "/api/setup/undo":
		failed := func(err error) error {
			c.log("undo failed: %v", err)
			return bad(fmt.Sprintf("Net Switch couldn’t undo the Windows changes: %v.", err))
		}
		if err := windowsundo.Validate(undo, aliases); err != nil {
			return failed(err)
		}
		unreachable := []string{}
		if v, ok := policy["value"]; ok {
			if _, err := c.op.Platform.Call(ctx, "policy-set", map[string]any{"value": v}); err != nil {
				return failed(err)
			}
			if _, err := c.op.Undo.Update(map[string]any{"policy": map[string]any{}}); err != nil {
				return failed(err)
			}
		}
		for _, alias := range aliases {
			record := metrics[alias]
			if len(array(record)) > 0 {
				if _, err := c.op.Platform.Call(ctx, "metrics-restore", map[string]any{"alias": alias, "metrics": record}); err != nil {
					unreachable = append(unreachable, alias)
					continue
				}
			}
			delete(metrics, alias)
			if _, err := c.op.Undo.Update(map[string]any{"metrics": windowsundo.MetricsJSON(metrics, aliases)}); err != nil {
				return failed(err)
			}
		}
		c.refreshPolicy(ctx)
		if err := c.RefreshAdapters(ctx); err != nil {
			return err
		}
		if len(unreachable) > 0 {
			return bad("Connect " + strings.Join(unreachable, " and ") + " again to finish undoing, then press Undo again.")
		}
		return nil
	}
	return c.RefreshAdapters(ctx)
}

func (c *Core) refreshPolicy(ctx context.Context) {
	if value, err := c.op.Platform.Call(ctx, "policy", nil); err == nil {
		c.mu.Lock()
		c.policy = value
		c.mu.Unlock()
	}
}
