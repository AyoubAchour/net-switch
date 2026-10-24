package control

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/crashnet"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
	"github.com/AyoubAchour/net-switch/internal/linehealth"
	"github.com/AyoubAchour/net-switch/internal/lines"
	"github.com/AyoubAchour/net-switch/internal/platform"
	"github.com/AyoubAchour/net-switch/internal/settings"
	"github.com/AyoubAchour/net-switch/internal/updates"
	"github.com/AyoubAchour/net-switch/internal/usage"
	"github.com/AyoubAchour/net-switch/internal/windowsundo"
)

type Clock interface {
	Now() time.Time
	After(time.Duration) <-chan time.Time
}
type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

type Options struct {
	LineID                 func() string
	Engine                 engine.Engine
	Platform               platform.System
	Settings               *settings.Store
	Undo                   *settings.Store
	Journal                *settings.Store
	IO                     settings.Options
	Clock                  Clock
	Location               *time.Location
	Mode, Version, UserDir string
	ID                     func() string
	Log                    func(string)
	Event                  func(map[string]any)
	Background             func(func())
	ProbeBackground        func(string, func())
	AutostartAllowed       bool
	CheckUpdate            func(context.Context) (*updates.Offer, error)
	Tracker                AppTracker
	Crash                  *crashnet.Net
	// ServiceMode changes durability and lifetime, while the old CI launcher
	// remains a behavior oracle until the engine swap.
	ServiceMode bool
	BootID      string
	Checkpoint  func(string)
}
type AppTracker interface {
	Reset()
	Ingest([]apps.Connection, int64)
	Snapshot(apps.Pins) []apps.Row
	LineRate(string) apps.Rate
	ConnectionIDsOffLine(string, string) []string
	// IdentityOf is the engine's sandbox identity for a tracked app, else "".
	IdentityOf(string) string
}
type lane struct {
	alias         string
	health        linehealth.Health
	generation    uint64
	target        *string
	delay         *float64
	probeAt       *int64
	routeReadAt   *int64
	routeSequence uint64
	probing       bool
	operator      int
	missingAt     *int64
	missingReads  int
	logged        map[string]int64
	sampled       bool
	ignoreAck     bool
}
type meter struct {
	counter usage.Counter
	rate    *apps.Rate
	at      int64
}
type Core struct {
	mu                                           sync.Mutex
	op                                           Options
	ctx                                          context.Context
	cancel                                       context.CancelFunc
	laneQueue, startQueue, setupQueue            *Queue
	values                                       map[string]any
	lanes                                        map[string]*lane
	adapters                                     []map[string]any
	routes                                       []map[string]any
	routesAt                                     int64
	networkSequence, routesSequence              uint64
	networkIssued                                atomic.Uint64
	meters                                       map[string]meter
	outsideAt                                    int64
	tracker                                      AppTracker
	outside                                      *apps.OutsideTracker
	outsideStarts                                map[string]string
	evidence                                     map[string]map[string]int64
	usage                                        *usage.Usage
	exhausted                                    map[string]bool
	closePending                                 map[string]bool
	deferClosures                                map[string]uint64
	pollSequence                                 uint64
	initialSampled                               bool
	connections                                  map[string]int
	info                                         map[string]map[string]any
	infoAttempted                                map[string]bool
	infoPending                                  []string
	infoQueued                                   map[string]bool
	infoRunning                                  bool
	installedMu                                  sync.Mutex
	installedCached                              []any
	installedSession                             atomic.Uint64
	installedCachedSession                       uint64
	installedExpires                             int64
	events                                       []map[string]any
	generation                                   uint64
	wanted, quitting, elevated                   bool
	powerSuspended                               bool
	powerGeneration                              uint64
	engineStarting, startReturned                bool
	startPowerGeneration                         uint64
	monitorFailures, scanFailures, retryAttempts int
	retryAt, elevationAt, sharesAt               int64
	ipv6Since                                    *int64
	policy                                       any
	autostart                                    any
	offer                                        *updates.Offer
	updateCheck                                  *updateCall
	lastUpdateFailure                            string
	lastStatus                                   string
	revision                                     uint64
	pendingRevision                              *engine.Revision
	pendingInstance                              string
	closures                                     []closureIntent
	closureRetries                               map[string]closureRetry
	applyMu                                      sync.Mutex
	saveMu                                       sync.Mutex
	failureTimes                                 []int64
	failureDirty                                 bool
	lastFailureID                                string
	// adapterLosses are clean adapter-loss exits in the last ten minutes. The
	// first three restart at once without touching failureTimes (spec §5.1).
	adapterLosses []int64
	totalsAt      int64
	totalsBusy    bool
	// usageWrite serialises every usage.json writer: the snapshot is taken and
	// written under it, so an older snapshot can never replace a newer one.
	usageWrite sync.Mutex
	// routedGeneration counts routed-usage changes; routedSaved is the last
	// generation written durably. Unequal means unacknowledged accounting is
	// not yet on disk, whatever the next engine read says.
	routedGeneration, routedSaved uint64
}

// adapterLossesFree is how many clean adapter losses in ten minutes restart
// without counting toward the five-failure latch.
const adapterLossesFree = 3

func New(ctx context.Context, o Options) (*Core, error) {
	if o.Engine == nil || o.Settings == nil || o.Platform == nil {
		return nil, fmt.Errorf("control requires engine, settings and platform")
	}
	if o.Clock == nil {
		o.Clock = realClock{}
	}
	if o.ID == nil {
		o.ID = func() string {
			var b [6]byte
			if _, err := rand.Read(b[:]); err != nil {
				panic(err)
			}
			return hex.EncodeToString(b[:])
		}
	}
	if o.Log == nil {
		o.Log = func(string) {}
	}
	if o.LineID == nil {
		o.LineID = lines.RandomID
	}
	if o.Background == nil {
		o.Background = func(f func()) { go f() }
	}
	if o.Mode == "" {
		o.Mode = "tun"
	}
	if o.Location == nil {
		var err error
		o.Location, err = usage.LocalLocation()
		if err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	c := &Core{op: o, ctx: ctx, cancel: cancel, values: o.Settings.Values(), lanes: map[string]*lane{}, adapters: []map[string]any{}, routes: []map[string]any{}, meters: map[string]meter{}, tracker: apps.NewTracker(), outside: apps.NewOutsideTracker(), usage: usage.New(o.Location), exhausted: map[string]bool{}, closePending: map[string]bool{}, connections: map[string]int{}, info: map[string]map[string]any{}, events: []map[string]any{}, wanted: true, lastStatus: "off"}
	if o.ServiceMode {
		c.wanted = false
	}
	if o.Tracker != nil {
		c.tracker = o.Tracker
	}
	c.infoAttempted = map[string]bool{}
	c.infoQueued = map[string]bool{}
	c.outsideStarts = map[string]string{}
	c.evidence = map[string]map[string]int64{}
	c.deferClosures = map[string]uint64{}
	c.closureRetries = map[string]closureRetry{}
	if c.op.Crash == nil {
		c.op.Crash = crashnet.New(o.Log, func(ctx context.Context) error {
			defer c.cancel()
			return o.Engine.Stop(ctx)
		})
	}
	background := c.op.Background
	c.op.Background = func(f func()) {
		background(func() { defer c.op.Crash.Recover("control background task"); f() })
	}
	c.laneQueue = newQueue(ctx, c.op.Crash)
	c.startQueue = newQueue(ctx, c.op.Crash)
	c.setupQueue = newQueue(ctx, c.op.Crash)
	if err := c.migrate(); err != nil {
		cancel()
		return nil, err
	}
	c.log("line readings come from native workers")
	if o.ServiceMode {
		c.log("network readings come from isolated platform workers")
	} else {
		c.log("network readings come from native workers (Windows change notifications)")
	}
	if o.IO.Files != nil {
		if b, err := o.IO.Files.ReadFile(filepath.Join(o.UserDir, "usage.json")); err == nil {
			if v, err := js.Decode(b); err == nil {
				c.usage.Load(js.Object(v))
				c.usage.Routed = usage.LoadRouted(b) // exact integers, not float64
			} else {
				c.log("could not read the data use record, starting it over: %v", err)
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			c.log("could not read the data use record, starting it over: %v", err)
		}
	}
	if o.Journal != nil {
		c.revision = uint64(js.Number(o.Journal.Values()["revision"]))
		var err error
		c.closures, err = readClosures(o.Journal.Values()["closures"])
		if err != nil {
			cancel()
			return nil, fmt.Errorf("read pending closures: %w", err)
		}
		if o.ServiceMode {
			c.wanted = o.Journal.Values()["bootId"] == o.BootID && o.BootID != "" && o.Journal.Values()["wanted"] == true
			raw := o.Journal.RawValues()
			if b := raw["desired"]; len(b) != 0 && string(b) != "null" {
				var desired engine.Revision
				if err := json.Unmarshal(b, &desired); err != nil {
					cancel()
					return nil, err
				}
				c.pendingRevision = &desired
				c.pendingInstance = js.Text(o.Journal.Values()["engineInstanceId"])
				if restore, ok := o.Engine.(interface{ Restore(*engine.Revision) }); ok {
					restore.Restore(&desired)
				}
			}
			if b := raw["settings"]; len(b) != 0 && string(b) != "null" {
				var saved map[string]json.RawMessage
				if err := json.Unmarshal(b, &saved); err != nil {
					cancel()
					return nil, err
				}
				changes := map[string]any{}
				for k, v := range saved {
					changes[k] = v
				}
				if c.values, err = o.Settings.Update(changes); err != nil {
					cancel()
					return nil, err
				}
			}
			_ = json.Unmarshal(raw["failures"], &c.failureTimes)
			_ = json.Unmarshal(raw["adapterLosses"], &c.adapterLosses)
			c.lastFailureID = js.Text(o.Journal.Values()["lastFailureId"])
			if c.wanted && len(c.failureTimes) >= 5 {
				o.Engine.Fail(fmt.Errorf("Routing stopped after five failures in ten minutes. Turn routing on to retry."))
				c.lastFailureID = o.Engine.Snapshot().FailureID
				c.lastStatus = "error"
			}
		}
	}
	c.syncLanesLocked()
	return c, nil
}
func (c *Core) now() int64                     { return c.op.Clock.Now().UnixMilli() }
func ptr[T any](v T) *T                        { return &v }
func (c *Core) log(format string, args ...any) { c.op.Log(fmt.Sprintf(format, args...)) }
func (c *Core) itemsLocked() []lines.Line {
	if v, ok := c.values["lines"].([]lines.Line); ok {
		return append([]lines.Line{}, v...)
	}
	return lines.NormalizeLines(c.values["lines"])
}
func (c *Core) pinsLocked() apps.Pins {
	p, _ := c.values["appLines"].(apps.Pins)
	if p == nil {
		return apps.Pins{}
	}
	return p
}
func (c *Core) save(changes map[string]any, remove ...string) error {
	if c.op.ServiceMode {
		c.applyMu.Lock()
		defer c.applyMu.Unlock()
	}
	c.saveMu.Lock()
	defer c.saveMu.Unlock()
	if changes == nil {
		changes = map[string]any{}
	}
	for _, k := range remove {
		changes[k] = settings.Delete
	}
	if c.op.ServiceMode {
		c.mu.Lock()
		old := c.values
		next := map[string]any{}
		for k, v := range old {
			next[k] = v
		}
		for k, v := range changes {
			if _, deleted := v.(struct{}); deleted {
				delete(next, k)
			} else {
				next[k] = v
			}
		}
		c.values = next
		p := c.policyLocked()
		intents := append([]closureIntent{}, c.closures...)
		c.mu.Unlock()
		if _, err := c.persistRevision(p, intents); err != nil {
			c.mu.Lock()
			c.values = old
			c.mu.Unlock()
			return err
		}
		// The journal is authoritative. Refresh the complete settings mirror,
		// including a previously committed change whose mirror write failed.
		changes = map[string]any{}
		for k, v := range next {
			changes[k] = v
		}
		for k := range c.op.Settings.Values() {
			if _, ok := next[k]; !ok {
				changes[k] = settings.Delete
			}
		}
	}
	v, err := c.op.Settings.Update(changes)
	if err != nil {
		if c.op.ServiceMode {
			c.log("desired settings committed; settings mirror will be repaired on the next save or restart: %v", err)
			return nil
		}
		return err
	}
	c.mu.Lock()
	c.values = v
	c.mu.Unlock()
	return nil
}
func (c *Core) migrate() error {
	v := c.values
	if old, ok := v["setupUndo"]; ok && c.op.Undo != nil {
		if m := js.Object(old); m != nil {
			u := c.op.Undo.Values()
			var rawOld map[string]json.RawMessage
			if err := json.Unmarshal(c.op.Settings.RawValues()["setupUndo"], &rawOld); err != nil {
				return err
			}
			// Node spreads the legacy entries first, then the current record.
			// Overwrites keep the original key position; new keys append. Keep
			// that raw order so a later partial Undo names adapters identically.
			aliases := windowsundo.Aliases(rawOld["metrics"])
			for _, alias := range windowsundo.Aliases(c.op.Undo.RawValues()["metrics"]) {
				if !slices.Contains(aliases, alias) {
					aliases = append(aliases, alias)
				}
			}
			metrics := js.Object(m["metrics"])
			if metrics == nil {
				metrics = map[string]any{}
			}
			for k, v := range js.Object(u["metrics"]) {
				metrics[k] = v
			}
			policy := js.Object(u["policy"])
			if policy == nil {
				policy = map[string]any{}
			}
			if _, ok := policy["value"]; !ok {
				if val, ok := m["policy"]; ok {
					policy["value"] = val
				}
			}
			if _, err := c.op.Undo.Update(map[string]any{"metrics": windowsundo.MetricsJSON(metrics, aliases), "policy": policy}); err != nil {
				return err
			}
		}
		if err := c.save(nil, "setupUndo"); err != nil {
			return err
		}
	}
	if m := lines.MigrateSettings(v, c.op.LineID); m != nil {
		b, err := js.Marshal(m.Lines)
		if err != nil {
			return err
		}
		ll, err := js.Decode(b)
		if err != nil {
			return err
		}
		ch := map[string]any{"lines": ll, "appLines": m.AppLines}
		if len(m.WaitingApps) > 0 {
			ch["waitingApps"] = m.WaitingApps
		}
		if err := c.save(ch, lines.LegacyKeys...); err != nil {
			return err
		}
		names := []string{}
		for _, line := range c.itemsLocked() {
			names = append(names, line.Label+" ("+line.Alias+")")
		}
		text := strings.Join(names, ", ")
		if text == "" {
			text = "none yet"
		}
		c.log("settings moved to lines: %s", text)
	} else {
		for _, k := range lines.LegacyKeys {
			if _, ok := v[k]; ok {
				if err := c.save(nil, lines.LegacyKeys...); err != nil {
					return err
				}
				break
			}
		}
	}
	items := c.itemsLocked()
	pins := apps.Pins{}
	ids := map[string]bool{}
	for _, l := range items {
		ids[l.ID] = true
	}
	for _, p := range c.pinsLocked() {
		if p.Path != "" && ids[p.LineID] {
			pins = append(pins, p)
		}
	}
	mode := js.Text(c.values["combineMode"])
	if mode != "auto" && mode != "manual" {
		mode = "auto"
	}
	ipv6 := js.Text(c.values["ipv6"])
	if ipv6 != "auto" && ipv6 != "off" {
		ipv6 = "auto"
	}
	b, _ := js.Marshal(items)
	raw, _ := js.Marshal(c.values["lines"])
	normalizedLines, _ := js.Decode(b)
	savedLines, _ := js.Decode(raw)
	if !reflect.DeepEqual(normalizedLines, savedLines) || !reflect.DeepEqual(pins, c.pinsLocked()) || mode != c.values["combineMode"] || ipv6 != c.values["ipv6"] {
		return c.save(map[string]any{"lines": items, "appLines": pins, "combineMode": mode, "ipv6": ipv6})
	}
	return nil
}
func (c *Core) syncLanesLocked() {
	keep := map[string]bool{}
	ids := []string{}
	for _, l := range c.itemsLocked() {
		keep[l.ID] = true
		ids = append(ids, l.ID)
		a := c.lanes[l.ID]
		if a == nil {
			a = &lane{}
			c.lanes[l.ID] = a
		}
		if a.alias != l.Alias {
			c.forgetLane(l.ID)
			delete(c.evidence, l.ID)
			a.alias = l.Alias
			a.generation++
			a.health.Reset()
			a.target = nil
			a.delay = nil
			a.probeAt = nil
			a.routeReadAt = nil
			a.routeSequence = 0
			a.probing = false
		}
	}
	for id := range c.lanes {
		if !keep[id] {
			delete(c.lanes, id)
		}
	}
	c.usage.KeepOnly(ids)
}
func (c *Core) resetLocked() {
	c.generation++
	c.tracker.Reset()
	c.outside.Reset()
	c.outsideStarts = map[string]string{}
	c.evidence = map[string]map[string]int64{}
	c.connections = map[string]int{}
	c.monitorFailures = 0
	for _, l := range c.lanes {
		l.generation++
		l.target = nil
		l.probeAt = nil
		l.routeReadAt = nil
		l.routeSequence = 0
		l.probing = false
		l.delay = nil
		l.health.RestartKeeping(l.health.Offline, l.health.AwaitingPass, c.now())
	}
}
func (c *Core) statusLocked(s engine.Snapshot) {
	// Poll may have sampled before Start or its asynchronous recovery finished.
	// Classify and settle the attempt from the same current observation.
	if c.engineStarting && c.startReturned {
		s = c.op.Engine.Snapshot()
	}
	// Windows can throttle services during Modern Standby. Neither an
	// observation while suspended nor a start spanning a power transition
	// is evidence for the crash latch. Keep genuine prior failures intact.
	if c.op.ServiceMode && (c.powerSuspended || c.engineStarting && c.startPowerGeneration != c.powerGeneration) && s.Status == "error" && s.FailureID != "" && s.FailureID != c.lastFailureID {
		c.lastFailureID = s.FailureID
		c.failureDirty = true
		c.log("engine start or exit crossed a power transition; retaining the existing crash budget")
	}
	// A start whose reply was lost returns while the engine is still starting;
	// Remote's connection recovery publishes the outcome later. The attempt and
	// its power classification last until Control observes that outcome.
	if c.engineStarting && c.startReturned && settledStatus(s.Status) {
		c.engineStarting = false
	}
	freshFailure := s.FailureID != "" && s.FailureID != c.lastFailureID
	if s.Status == c.lastStatus && (!c.op.ServiceMode || !freshFailure) {
		return
	}
	c.lastStatus = s.Status
	if s.Status != "on" {
		c.resetLocked()
	}
	if s.Status == "error" && c.wanted && !c.quitting && c.op.ServiceMode && freshFailure && s.Reason == engine.ReasonAdapterLost && c.adapterLossIsFreeLocked() {
		// A clean adapter loss (exit 3, cleanup complete) restarts at once and
		// leaves the crash budget alone. The window makes a flapping driver
		// fall through to the ordinary path below on its fourth loss.
		c.lastFailureID = s.FailureID
		c.failureDirty = true
		c.retryAt = c.now()
		c.log("adapter lost; restarting routing without counting a failure (%d of %d in ten minutes)", len(c.adapterLosses), adapterLossesFree)
	} else if s.Status == "error" && c.wanted && !c.quitting && (!c.op.ServiceMode || freshFailure) {
		d := []int64{5000, 15000, 30000, 60000}
		if c.op.ServiceMode {
			c.lastFailureID = s.FailureID
			d = []int64{1000, 2000, 5000, 30000}
			if s.Reason == engine.ReasonAdapterLost {
				c.log("adapter lost again; this loss counts toward the five-failure budget")
			}
			recent := c.failureTimes[:0]
			for _, at := range c.failureTimes {
				if at > c.now()-10*60000 {
					recent = append(recent, at)
				}
			}
			c.failureTimes = append(recent, c.now())
			c.failureDirty = true
			if len(c.failureTimes) >= 5 {
				c.op.Engine.Fail(fmt.Errorf("Routing stopped after five failures in ten minutes. Turn routing on to retry."))
			}
		}
		c.retryAt = c.now() + d[min(c.retryAttempts, len(d)-1)]
		c.retryAttempts++
	}
	msg := "routing " + s.Status
	if s.Error != nil {
		msg += ": " + *s.Error
	}
	c.log("%s", msg)
}
func settledStatus(status string) bool { return status == "on" || status == "off" || status == "error" }

// adapterLossIsFreeLocked records one clean adapter loss and reports whether it
// is within the free allowance. Losses older than ten minutes fall out first.
func (c *Core) adapterLossIsFreeLocked() bool {
	now := c.now()
	recent := c.adapterLosses[:0]
	for _, at := range c.adapterLosses {
		if at > now-10*60000 {
			recent = append(recent, at)
		}
	}
	c.adapterLosses = append(recent, now)
	return len(c.adapterLosses) <= adapterLossesFree
}
func (c *Core) noteLocked(kind, id, text string) {
	e := map[string]any{"id": c.op.ID(), "at": c.now(), "kind": kind, "lineId": id, "text": text}
	c.events = append(c.events, e)
	if len(c.events) > 20 {
		c.events = c.events[len(c.events)-20:]
	}
	if c.op.Event != nil {
		c.op.Event(e)
	}
}
func (c *Core) policyLocked() engine.Policy {
	items := c.itemsLocked()
	up := map[string]bool{}
	for id, l := range c.lanes {
		up[id] = l.health.Up != nil && *l.health.Up
	}
	p := engine.Policy{Lines: items, AppLines: append(apps.Pins{}, c.pinsLocked()...), Combine: js.Truth(c.values["combine"]), Shares: c.sharesLocked(items), Blocked: []string{}, Lanes: map[string]string{}, IPv6: c.ipv6Locked()}
	current := c.op.Engine.Snapshot()
	if p.Combine && current.Policy.Combine && c.values["combineMode"] == "auto" && len(p.Shares) == len(current.Policy.Shares) {
		sameIDs, moved := true, false
		for i, share := range p.Shares {
			sameIDs = sameIDs && share.ID == current.Policy.Shares[i].ID
			moved = moved || math.Abs(share.Value-current.Policy.Shares[i].Value) >= .1-1e-9
		}
		if sameIDs && (c.now()-c.sharesAt < 60000 || !moved) {
			p.Shares = append(lines.Shares{}, current.Policy.Shares...)
		}
	}
	for i, l := range items {
		t := lines.LaneTarget(items, l.ID, up, c.exhausted)
		if t != nil {
			p.Lanes[l.ID] = *t
			if i > 0 && c.exhausted[l.ID] && *t == l.ID {
				p.Blocked = append(p.Blocked, l.ID)
			}
		}
	}
	return p
}
func (c *Core) sharesLocked(items []lines.Line) lines.Shares {
	sharing := lines.SharingLines(items, c.exhausted)
	if len(sharing) < 2 {
		return lines.Shares{}
	}
	weights := map[string]any{}
	if c.values["combineMode"] == "manual" {
		for _, l := range sharing {
			weights[l.ID] = l.Weight
		}
	} else {
		for k, v := range c.usage.AutoWeights(sharing) {
			weights[k] = v
		}
	}
	return lines.SharesFromWeights(sharing, weights)
}
func (c *Core) ipv6Locked() bool {
	items := c.itemsLocked()
	if c.values["ipv6"] == "off" || len(items) == 0 {
		return false
	}
	for _, l := range items {
		found := false
		for _, a := range c.adapters {
			if a["alias"] == l.Alias && a["ipv6"] == true {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func (c *Core) CheckElevation(ctx context.Context) {
	v, err := c.op.Platform.Call(ctx, "elevated", nil)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.elevationAt = c.now()
	if err == nil {
		c.elevated = v == true
	}
}

// SetPowerSuspended changes recovery scheduling, never the owner's intent or
// existing failure budget. A resume also identifies attempts spanning a wake.
func (c *Core) SetPowerSuspended(suspended bool) {
	if !c.op.ServiceMode {
		return
	}
	c.mu.Lock()
	c.powerSuspended = suspended
	c.powerGeneration++
	c.mu.Unlock()
}

func (c *Core) Start(ctx context.Context) error {
	ctx = c.ctx
	return c.startQueue.Do(ctx, func() error {
		if c.op.ServiceMode {
			c.mu.Lock()
			blocked := len(c.failureTimes) >= 5 || c.now() < c.retryAt || c.powerSuspended
			c.mu.Unlock()
			if blocked {
				return nil
			}
			if err := c.ApplyPolicy(ctx); err != nil {
				return err
			}
		}
		c.mu.Lock()
		if !c.wanted || c.quitting || c.powerSuspended {
			c.mu.Unlock()
			return nil
		}
		if c.op.Mode == "tun" && !c.elevated {
			c.op.Engine.Fail(fmt.Errorf("Net Switch needs administrator rights to move apps between connections. Close it and open it again from the Net Switch shortcut."))
			c.statusLocked(c.op.Engine.Snapshot())
			c.mu.Unlock()
			return nil
		}
		p := c.policyLocked()
		if c.op.ServiceMode && len(p.Lines) == 0 {
			c.mu.Unlock()
			return nil
		}
		current := c.op.Engine.Snapshot()
		if len(p.Lines) > 0 && current.Status != "on" && current.Status != "starting" {
			c.statusLocked(engine.Snapshot{Status: "starting"})
		}
		c.engineStarting = true
		c.startReturned = false
		c.startPowerGeneration = c.powerGeneration
		c.mu.Unlock()
		if err := c.op.Engine.Start(ctx, p); err != nil {
			c.mu.Lock()
			c.startReturned = true
			c.statusLocked(c.op.Engine.Snapshot())
			c.mu.Unlock()
			if c.op.ServiceMode {
				c.applyMu.Lock()
				_ = c.persistJournal()
				c.applyMu.Unlock()
			}
			return err
		}
		c.mu.Lock()
		c.startReturned = true
		c.statusLocked(c.op.Engine.Snapshot())
		for _, lane := range c.lanes {
			// Node's wanted() samples an uninitialised LaneSwitch, changing
			// its generation and discarding the first selector acknowledgement.
			// New lanes can still need this after an explicit Start/rebind.
			lane.ignoreAck = !lane.sampled
		}
		c.sampleLinesLocked(c.op.Engine.Snapshot())
		c.mu.Unlock()
		if c.op.Engine.Snapshot().Status != "on" {
			return nil
		}
		if err := c.ApplyPolicy(ctx); err != nil {
			return err
		}
		c.scheduleProbes(ctx, nil)
		return c.ReplayClosures(ctx)
	})
}
func (c *Core) Routing(ctx context.Context, on bool) error {
	ctx = c.ctx
	// Turning routing on is a fresh intent with a full retry budget.
	next := routingIntent{wanted: on, fresh: on}
	if c.op.ServiceMode {
		c.applyMu.Lock()
		err := c.commitIntent(next)
		c.applyMu.Unlock()
		if err != nil {
			return err
		}
	} else {
		c.mu.Lock()
		c.publishIntentLocked(next)
		c.mu.Unlock()
	}
	if c.op.ServiceMode && !on {
		c.checkpoint("control-after-stop-intent")
	}
	if on {
		return c.Start(ctx)
	}
	return c.startQueue.Do(ctx, func() error {
		c.mu.Lock()
		if c.op.Engine.Snapshot().Status == "on" {
			c.statusLocked(engine.Snapshot{Status: "stopping"})
		}
		c.mu.Unlock()
		err := c.op.Engine.Stop(ctx)
		c.mu.Lock()
		c.statusLocked(c.op.Engine.Snapshot())
		c.mu.Unlock()
		return err
	})
}

// SignIn acknowledges durable intent. Only the supervisor attempts an engine
// start, so desktop handshakes cannot bypass its retry schedule.
func (c *Core) SignIn(ctx context.Context) error {
	if !c.op.ServiceMode {
		return c.Routing(ctx, true)
	}
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	c.mu.Lock()
	// A new sign-in after logoff is a fresh routing intent. Repeated
	// handshakes while that intent is already on keep its retry budget.
	// applyMu keeps wanted from changing before the commit.
	fresh := !c.wanted
	c.mu.Unlock()
	return c.commitIntent(routingIntent{wanted: true, fresh: fresh})
}

// ResumeRouting preserves the crash budget when SCM restarts Control.
func (c *Core) ResumeRouting(ctx context.Context) error {
	if !c.WantsRouting() {
		return c.op.Engine.Stop(ctx)
	}
	return c.Start(ctx)
}
func (c *Core) WantsRouting() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.wanted }
func (c *Core) restart(ctx context.Context) error {
	ctx = c.ctx
	c.mu.Lock()
	if c.op.Engine.Snapshot().Status == "on" {
		c.statusLocked(engine.Snapshot{Status: "stopping"})
	}
	c.mu.Unlock()
	if err := c.op.Engine.Stop(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	c.statusLocked(c.op.Engine.Snapshot())
	c.mu.Unlock()
	return c.Start(ctx)
}
func (c *Core) ApplyPolicy(ctx context.Context) error {
	return c.applyPolicy(ctx, false)
}
func (c *Core) applyPolicy(ctx context.Context, auto bool) error {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	c.saveMu.Lock()
	defer c.saveMu.Unlock()
	c.mu.Lock()
	p := c.policyLocked()
	gen := c.generation
	s := c.op.Engine.Snapshot()
	pending := c.pendingRevision
	if auto && !p.Combine {
		p.Shares = append(lines.Shares{}, s.Policy.Shares...)
	}
	c.mu.Unlock()
	sameRevision := !c.op.ServiceMode || pending != nil && pending.Number == s.AppliedRevision && pending.Hash == s.AppliedHash
	if reflect.DeepEqual(p, s.Policy) && s.AppliedRevision != 0 && sameRevision {
		if c.op.ServiceMode {
			c.mu.Lock()
			changed := c.pendingInstance != s.Instance
			if changed {
				c.pendingInstance = s.Instance
				c.pendingRevision = &engine.Revision{Number: s.AppliedRevision, Hash: s.AppliedHash, Policy: p}
				c.revision = max(c.revision, s.AppliedRevision)
			}
			c.mu.Unlock()
			if changed {
				return c.persistJournal()
			}
		}
		return nil
	}
	intents, err := c.pendingClosures()
	if err != nil {
		return err
	}
	intents, err = c.reconcileIntents(intents, p)
	if err != nil {
		return err
	}
	revision, err := c.persistRevision(p, intents)
	if err != nil {
		return err
	}
	ack, err := c.op.Engine.Apply(ctx, revision)
	if err != nil {
		return err
	}
	if ack.Number != revision.Number || ack.Hash != revision.Hash {
		return fmt.Errorf("engine acknowledged a different revision")
	}
	c.checkpoint("control-after-apply-ack")
	if err := c.recordIntentAcks(intents, ack); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if gen != c.generation {
		return nil
	}
	c.recordLanesLocked(p)
	if !reflect.DeepEqual(s.Policy.Shares, p.Shares) {
		c.sharesAt = c.now()
	}
	c.logPolicyRulesLocked(s.Policy, p, auto)
	return nil
}

func (c *Core) checkpoint(point string) {
	if c.op.Checkpoint != nil {
		c.op.Checkpoint(point)
	}
}

func (c *Core) recordLanesLocked(p engine.Policy) {
	active := c.op.Engine.Snapshot()
	if active.Status != "on" || active.StartedWith == nil || len(active.StartedWith.Lines) < 2 {
		return
	}
	for _, line := range p.Lines {
		id, target := line.ID, p.Lanes[line.ID]
		if l := c.lanes[id]; l != nil && (l.target == nil || *l.target != target) {
			if l.ignoreAck {
				// Preserve Node's discarded first switch, then force one real
				// retry even when the adapter already points at this target.
				l.ignoreAck = false
				c.forgetLane(id)
				continue
			}
			l.target = ptr(target)
			c.log("%s's apps now use %s", c.labelLocked(id), c.labelLocked(target))
		}
	}
}

func (c *Core) forgetLane(id string) {
	if adapter, ok := c.op.Engine.(interface{ ForgetLane(string) }); ok {
		adapter.ForgetLane(id)
	}
}

func (c *Core) logPolicyRulesLocked(before, after engine.Policy, auto bool) {
	if auto && after.Combine && !reflect.DeepEqual(before.Shares, after.Shares) {
		text := []string{}
		for _, s := range after.Shares {
			text = append(text, fmt.Sprintf("%s %d%%", c.labelLocked(s.ID), int(math.Round(s.Value*100))))
		}
		c.log("combining shares: %s", strings.Join(text, ", "))
	}
	if !reflect.DeepEqual(before.Blocked, after.Blocked) {
		for _, id := range after.Blocked {
			c.log("%s is out of data and no other line can take its apps: their new connections are refused until the cap resets", c.labelLocked(id))
		}
	}
}
func (c *Core) labelLocked(id string) string {
	for _, l := range c.itemsLocked() {
		if l.ID == id {
			return l.Label
		}
	}
	return id
}
func (c *Core) Supervise(ctx context.Context) error {
	if c.op.ServiceMode {
		defer c.persistFailureBudget()
	}
	c.mu.Lock()
	recheck := c.op.Mode == "tun" && !c.elevated && c.now()-c.elevationAt >= 30000
	c.mu.Unlock()
	if recheck {
		c.CheckElevation(ctx)
	}
	s := c.op.Engine.Snapshot()
	c.mu.Lock()
	// Node runs the initial poll before its supervisor. Both Go loops can be
	// scheduled first, so make that initial sample an explicit prerequisite.
	// Otherwise scheduler order decides whether the first lane answer is lost.
	if !c.initialSampled {
		c.sampleLinesLocked(s)
	}
	c.statusLocked(s)
	if c.quitting || !c.wanted || c.powerSuspended {
		c.mu.Unlock()
		return nil
	}
	now := c.now()
	if c.op.Mode == "tun" && !c.elevated {
		c.mu.Unlock()
		if s.Status != "error" {
			return c.Start(ctx)
		}
		return nil
	}
	if s.Status == "on" {
		if now-s.StartedAt.UnixMilli() >= 120000 {
			c.retryAttempts = 0
		}
		// Service liveness comes from the lease and verified process lifetime.
		// Slow flow snapshots under CPU pressure do not prove engine death.
		restart := !c.op.ServiceMode && c.monitorFailures >= 20
		settledIPv6 := false
		if s.StartedWith != nil {
			restart = restart || c.bindingChangedLocked(s)
			if c.ipv6Locked() == s.StartedWith.IPv6 {
				c.ipv6Since = nil
			} else if c.ipv6Since == nil {
				c.ipv6Since = ptr(now)
			} else if now-*c.ipv6Since >= 30000 {
				restart = true
				settledIPv6 = true
				c.ipv6Since = nil
			}
		}
		c.mu.Unlock()
		if restart {
			return c.laneQueue.Do(ctx, func() error {
				c.mu.Lock()
				fresh := c.op.Engine.Snapshot()
				hung := !c.op.ServiceMode && c.monitorFailures >= 20
				rebound := c.bindingChangedLocked(fresh)
				needed := hung || rebound
				if fresh.StartedWith != nil {
					needed = needed || (settledIPv6 && c.ipv6Locked() != fresh.StartedWith.IPv6)
				}
				needed = needed && c.wanted && !c.quitting && fresh.Status == "on"
				if needed && hung {
					c.log("the routing engine hasn't answered for %d polls; restarting it", c.monitorFailures)
				} else if needed && rebound {
					aliases := []string{}
					for _, line := range c.itemsLocked() {
						aliases = append(aliases, line.Alias)
					}
					c.log("routing restarts to use %s", strings.Join(aliases, ", "))
				} else if needed && settledIPv6 {
					if c.ipv6Locked() {
						c.log("every line has IPv6 now: routing restarts to carry it too")
					} else {
						c.log("a line lost IPv6: routing restarts to keep apps on IPv4")
					}
				}
				c.mu.Unlock()
				if !needed {
					return nil
				}
				return c.restart(ctx)
			})
		}
		return nil
	}
	ready := (s.Status == "off" || s.Status == "error") && now >= c.retryAt
	if c.op.ServiceMode && len(c.failureTimes) >= 5 {
		ready = false
	}
	c.mu.Unlock()
	if ready {
		// A failure or adapter loss observed this tick is durable before the
		// restart it allows. While the budget cannot be written, no restart
		// happens: a crash during it would otherwise forget the failure.
		if err := c.persistFailureBudget(); err != nil {
			return fmt.Errorf("engine restart held back until the crash budget is durable: %w", err)
		}
		return c.Start(ctx)
	}
	return nil
}
func (c *Core) persistFailureBudget() error {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	c.mu.Lock()
	dirty := c.failureDirty
	c.failureDirty = false
	c.mu.Unlock()
	if !dirty {
		return nil
	}
	if err := c.persistJournal(); err != nil {
		c.mu.Lock()
		c.failureDirty = true
		c.mu.Unlock()
		c.log("cannot persist engine crash budget: %v", err)
		return err
	}
	return nil
}
func (c *Core) bindingChangedLocked(s engine.Snapshot) bool {
	if s.StartedWith == nil {
		return false
	}
	items := c.itemsLocked()
	if len(items) != len(s.StartedWith.Lines) {
		return true
	}
	for i, line := range items {
		if line.ID != s.StartedWith.Lines[i].ID || line.Alias != s.StartedWith.Lines[i].Alias {
			return true
		}
	}
	return false
}
func (c *Core) SaveUsage() error {
	c.usageWrite.Lock()
	defer c.usageWrite.Unlock()
	c.mu.Lock()
	b, err := js.Marshal(c.usage.Saved)
	generation := c.routedGeneration
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if err := settings.AtomicWrite(filepath.Join(c.op.UserDir, "usage.json"), b, c.op.IO); err != nil {
		return err
	}
	c.mu.Lock()
	if generation > c.routedSaved {
		c.routedSaved = generation
	}
	c.mu.Unlock()
	return nil
}
func (c *Core) Shutdown(ctx context.Context) error {
	// quitting holds off new starts while the stop intent is written. It is
	// not intent: a refused write puts it back and leaves wanted untouched.
	c.mu.Lock()
	wasQuitting := c.quitting
	c.quitting = true
	c.mu.Unlock()
	if c.op.ServiceMode {
		c.applyMu.Lock()
		err := c.commitIntent(routingIntent{wanted: false})
		c.applyMu.Unlock()
		if err != nil {
			c.mu.Lock()
			c.quitting = wasQuitting
			c.mu.Unlock()
			return err
		}
	}
	err := c.startQueue.Do(ctx, func() error {
		c.mu.Lock()
		if s := c.op.Engine.Snapshot(); s.Status == "on" || s.PID != 0 {
			c.statusLocked(engine.Snapshot{Status: "stopping"})
		}
		c.mu.Unlock()
		err := c.op.Engine.Stop(ctx)
		c.mu.Lock()
		c.statusLocked(c.op.Engine.Snapshot())
		c.mu.Unlock()
		return err
	})
	if err != nil {
		c.mu.Lock()
		c.quitting = false
		c.mu.Unlock()
		c.log("quit failed: %v", err)
		return err
	}
	if err := c.SaveUsage(); err != nil {
		c.log("could not save the data use record: %v", err)
	}
	if c.op.IO.Files != nil {
		if err := c.op.IO.Files.Remove(filepath.Join(c.op.UserDir, "server.json")); err != nil && !errors.Is(err, fs.ErrNotExist) {
			c.log("could not remove server.json: %v", err)
		}
	}
	c.cancel()
	c.log("quit")
	return nil
}

func (c *Core) Announce(port int) {
	c.mu.Lock()
	elevated := c.elevated
	c.mu.Unlock()
	c.log("started on port %d (mode %s, elevated %t)", port, c.op.Mode, elevated)
}

var wifiKind = regexp.MustCompile(`(?i)802\.11|wireless|wi-?fi|wlan`)
var phoneKind = regexp.MustCompile(`(?i)remote ndis|rndis|apple mobile device ethernet|internet sharing`)

func prepareAdapters(v any) ([]map[string]any, error) {
	list, ok := v.([]any)
	if !ok || len(list) == 0 {
		return nil, fmt.Errorf("Windows returned no network adapters")
	}
	out := []map[string]any{}
	for _, v := range list {
		a := js.Object(v)
		if a == nil || a["alias"] == "NetSwitch" {
			continue
		}
		txt := js.Text(a["mediaType"]) + " " + js.Text(a["description"])
		kind := "wired"
		if wifiKind.MatchString(txt) {
			kind = "wifi"
		} else if phoneKind.MatchString(txt) {
			kind = "phone"
		}
		a["kind"] = kind
		a["connected"] = a["status"] == "Up" && js.Truth(a["gateway"])
		out = append(out, a)
	}
	return out, nil
}
func (c *Core) RefreshAdapters(ctx context.Context) error {
	sequence := c.networkIssued.Add(1)
	c.mu.Lock()
	gen := c.generation
	c.mu.Unlock()
	v, err := c.op.Platform.Call(ctx, "network", nil)
	if err != nil {
		c.mu.Lock()
		c.scanFailures++
		c.mu.Unlock()
		return err
	}
	return c.ApplyNetwork(ctx, js.Object(v), gen, sequence)
}
func (c *Core) ApplyNetwork(ctx context.Context, v map[string]any, gen, sequence uint64) error {
	a, err := prepareAdapters(v["adapters"])
	if err != nil {
		return err
	}
	c.mu.Lock()
	readAt := int64(js.Number(v["readAt"]))
	// Sequence is owned by Control, so neither wall-clock corrections nor a
	// restarted worker can move the stream backwards. One-shot reads reserve
	// their position before dispatch; a late completion cannot overwrite a
	// streamed update already received while that request was in flight.
	if gen != c.generation || sequence <= c.networkSequence {
		c.mu.Unlock()
		return nil
	}
	c.networkSequence = sequence
	c.adapters = a
	c.scanFailures = 0
	if v["policy"] != "unknown" {
		c.policy = v["policy"]
		if c.policy == "absent" {
			c.policy = nil
		}
	}
	if rr, ok := v["defaultRoutes"].([]any); ok {
		c.routes = []map[string]any{}
		for _, r := range rr {
			c.routes = append(c.routes, js.Object(r))
		}
		c.routesAt = readAt
		c.routesSequence = sequence
	}
	c.mu.Unlock()
	return c.laneQueue.Do(ctx, func() error { return c.followAdapters() })
}
func (c *Core) followAdapters() error {
	c.mu.Lock()
	items := c.itemsLocked()
	adapters := c.adapters
	now := c.now()
	changed := false
	notes := []string{}
	renamed := [][2]string{}
	if len(items) == 0 {
		if a := lines.PickFirstAdapter(adapters); a != nil {
			items = append(items, lines.NewLine(a, nil, c.op.LineID))
			changed = true
			notes = append(notes, js.Text(a["alias"])+" is the main line")
		}
	}
	normalize := func(s string) string { return strings.ToLower(strings.NewReplacer("{", "", "}", "").Replace(s)) }
	for i, l := range items {
		var found map[string]any
		for _, a := range adapters {
			if l.GUID != nil && normalize(js.Text(a["guid"])) == normalize(*l.GUID) {
				found = a
				break
			}
		}
		if found == nil {
			for _, a := range adapters {
				if a["alias"] == l.Alias {
					found = a
					break
				}
			}
		}
		ln := c.lanes[l.ID]
		if ln == nil {
			continue
		}
		if found != nil {
			ln.missingAt = nil
			ln.missingReads = 0
			alias := js.Text(found["alias"])
			guid := js.Text(found["guid"])
			if alias != l.Alias {
				notes = append(notes, fmt.Sprintf("%s's adapter was renamed from %s to %s", l.Label, l.Alias, alias))
				renamed = append(renamed, [2]string{l.Alias, alias})
			}
			if alias != l.Alias || (guid != "" && (l.GUID == nil || *l.GUID != guid)) {
				items[i].Alias = alias
				if guid != "" {
					items[i].GUID = &guid
				}
				changed = true
			}
			continue
		}
		if ln.missingAt == nil {
			ln.missingAt = ptr(now)
		}
		ln.missingReads++
		if i != 0 || l.Kind == nil || *l.Kind != "wired" || ln.missingReads < 2 || now-*ln.missingAt < 20000 {
			continue
		}
		candidates := []map[string]any{}
		for _, a := range adapters {
			taken := false
			for _, other := range items {
				if other.Alias == a["alias"] {
					taken = true
				}
			}
			if !taken && a["kind"] == "wired" {
				candidates = append(candidates, a)
			}
		}
		if a := lines.PickFirstAdapter(candidates); a != nil {
			notes = append(notes, fmt.Sprintf("%s's adapter %s is gone; using %s instead", l.Label, l.Alias, js.Text(a["alias"])))
			items[i].Alias = js.Text(a["alias"])
			g := js.Text(a["guid"])
			items[i].GUID = &g
			changed = true
		}
	}
	c.mu.Unlock()
	if !changed {
		return nil
	}
	if err := c.save(map[string]any{"lines": items}); err != nil {
		return err
	}
	for _, note := range notes {
		c.log("%s", note)
	}
	if c.op.Undo != nil && len(renamed) > 0 {
		metrics := js.Object(c.op.Undo.Values()["metrics"])
		moved := false
		for _, pair := range renamed {
			if len(array(metrics[pair[0]])) == 0 {
				continue
			}
			if len(array(metrics[pair[1]])) == 0 {
				metrics[pair[1]] = metrics[pair[0]]
			}
			delete(metrics, pair[0])
			moved = true
		}
		if moved {
			if _, err := c.op.Undo.Update(map[string]any{"metrics": metrics}); err != nil {
				return err
			}
		}
	}
	c.mu.Lock()
	c.syncLanesLocked()
	c.mu.Unlock()
	return nil
}

func (c *Core) HelperLine(data []byte) bool {
	v, err := js.Decode(data)
	if err != nil {
		return false
	}
	m := js.Object(v)
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if list, ok := m["adapters"].([]any); ok {
		next := map[string]meter{}
		for _, v := range list {
			a := js.Object(v)
			alias := js.Text(a["alias"])
			if alias == "" {
				continue
			}
			counter := usage.Counter{RX: js.Number(a["rx"]), TX: js.Number(a["tx"])}
			var rate *apps.Rate
			if before, ok := c.meters[alias]; ok {
				sec := math.Max(.2, float64(now-before.at)/1000)
				rate = &apps.Rate{Down: math.Max(0, counter.RX-before.counter.RX) / sec, Up: math.Max(0, counter.TX-before.counter.TX) / sec}
			}
			next[alias] = meter{counter, rate, now}
		}
		c.meters = next
	}
	if list, ok := m["outside"].([]any); ok {
		c.outsideStarts = map[string]string{}
		c.outsideAt = now
		s := c.op.Engine.Snapshot()
		if s.Status != "on" {
			return true
		}
		owners := map[string]string{}
		for _, l := range c.itemsLocked() {
			for _, a := range c.adapters {
				if a["alias"] == l.Alias {
					for _, ip := range array(a["ipv4s"]) {
						addr := js.Text(ip)
						if _, ok := owners[addr]; !ok {
							owners[addr] = l.ID
						}
					}
				}
			}
		}
		samples := []apps.OutsideSample{}
		for _, v := range list {
			a := js.Object(v)
			id := owners[js.Text(a["local"])]
			if id == "" || int(js.Number(a["pid"])) == s.PID {
				continue
			}
			created, _ := time.Parse(time.RFC3339Nano, js.Text(a["created"]))
			var down, up *float64
			if a["down"] != nil {
				down = ptr(js.Number(a["down"]))
			}
			if a["up"] != nil {
				up = ptr(js.Number(a["up"]))
			}
			samples = append(samples, apps.OutsideSample{ID: js.Text(a["id"]), Path: js.Text(a["path"]), Line: id, Down: down, Up: up, BeforeRouting: created.Before(s.StartedAt)})
			c.outsideStarts[js.Text(a["id"])] = js.Text(a["processStarted"])
		}
		c.outside.Ingest(samples, now)
	}
	return true
}

func array(v any) []any { a, _ := v.([]any); return a }
