// Package flows owns admission reservations and cumulative accounting. The
// same lock makes revision apply points and flow admission totally ordered.
package flows

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
)

var ErrBudget = errors.New("routing capacity exhausted")
var ErrStopped = errors.New("routing is not running")
var ErrStale = errors.New("stale revision")
var ErrConflict = errors.New("revision conflict")

type StateStore interface{ SaveApplied(policy.Applied) error }
type Record struct {
	ID             uint64         `json:"id"`
	Epoch          uint64         `json:"epoch"`
	Start          time.Time      `json:"start"`
	Point          uint64         `json:"point"`
	Owner          platform.Owner `json:"app"`
	Protocol       string         `json:"protocol"`
	Source         netip.AddrPort `json:"source"`
	Destination    netip.AddrPort `json:"destination"`
	PhysicalSource netip.Addr     `json:"physicalSource"`
	flowapi.Decision
	Up      uint64 `json:"up"`
	Down    uint64 `json:"down"`
	Closing bool   `json:"closing"`
}
type Bytes struct {
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}
type Totals struct {
	Apps  map[string]Bytes `json:"apps"`
	Lines map[string]Bytes `json:"lines"`
}
type Gauges struct {
	Flows, Handshakes, UDP, Unknown, UnknownUDP                                                       int
	TCPBytes, PendingBytes, SnapshotBytes                                                             int64
	Rejected, DroppedNotices, Admitted, LookupCount, LookupMisses, LookupAmbiguous, LookupNanoseconds uint64
}
type counts struct{ flows, udp int }
type Table struct {
	mu                   sync.Mutex
	limits               Limits
	now                  func() time.Time
	store                StateStore
	policy               *policy.Policy
	applied              *policy.Applied
	epoch, nextID, point uint64
	k                    atomic.Uint64
	flows                map[uint64]*ticket
	apps                 map[string]counts
	totals               Totals
	gauges               Gauges
	snapshots            map[uint64]*snapshot
	nextSnapshot         uint64
	rejectSecond         int64
	rejectTotal          int
	rejectApps           map[string]int
}

func New(l Limits, store StateStore) *Table {
	return &Table{limits: l, now: time.Now, store: store, flows: map[uint64]*ticket{}, apps: map[string]counts{}, totals: Totals{Apps: map[string]Bytes{}, Lines: map[string]Bytes{}}, snapshots: map[uint64]*snapshot{}, rejectApps: map[string]int{}}
}
func (t *Table) SetEpoch(epoch uint64) { t.mu.Lock(); t.epoch = epoch; t.mu.Unlock() }
func (t *Table) Applied() *policy.Applied {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.applied == nil {
		return nil
	}
	a := *t.applied
	return &a
}
func (t *Table) Apply(r policy.Revision) (policy.Applied, error) {
	p, err := policy.Compile(r)
	if err != nil {
		return policy.Applied{}, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.applied != nil {
		if r.N < t.applied.N {
			return policy.Applied{}, ErrStale
		}
		if r.N == t.applied.N {
			if r.Hash != t.applied.Hash {
				return policy.Applied{}, ErrConflict
			}
			return *t.applied, nil
		}
	}
	a := policy.Applied{N: r.N, Hash: r.Hash, Point: t.point + 1}
	if t.store != nil {
		if err := t.store.SaveApplied(a); err != nil {
			return policy.Applied{}, err
		}
	}
	t.point = a.Point
	t.policy = p
	t.applied = &a
	return a, nil
}
func (t *Table) Unload() { t.mu.Lock(); t.policy = nil; t.applied = nil; t.mu.Unlock() }
func (t *Table) Predict(app string) (policy.Prediction, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.policy == nil {
		return policy.Prediction{}, ErrStopped
	}
	return t.policy.Predict(app), nil
}

func (t *Table) Begin(protocol string, tuple platform.Tuple) (flowapi.Ticket, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.policy == nil {
		return nil, ErrStopped
	}
	if protocol != "tcp" && protocol != "udp" {
		return nil, errors.New("unknown transport")
	}
	if !tuple.Source.IsValid() || !tuple.Destination.IsValid() {
		return nil, errors.New("invalid tuple")
	}
	if t.gauges.Flows >= t.limits.Flows || (protocol == "udp" && t.gauges.UDP >= t.limits.UDP) || (protocol == "tcp" && (t.gauges.Handshakes >= t.limits.Handshakes || t.gauges.TCPBytes+MinTCP > t.limits.TCPBytes)) {
		t.gauges.Rejected++
		return nil, ErrBudget
	}
	t.nextID++
	f := &ticket{table: t, record: Record{ID: t.nextID, Epoch: t.epoch, Start: t.now(), Protocol: protocol, Source: tuple.Source, Destination: tuple.Destination}}
	t.gauges.Flows++
	if protocol == "udp" {
		t.gauges.UDP++
	} else {
		f.handshake = true
		f.tcpBytes = MinTCP
		f.receive, f.send = 64<<10, 64<<10
		t.gauges.Handshakes++
		t.gauges.TCPBytes += MinTCP
	}
	t.flows[f.record.ID] = f
	return f, nil
}

type ticket struct {
	table                       *Table
	record                      Record
	resolved, closed, handshake bool
	tcpBytes                    int64
	receive, send               int
	cancel                      context.CancelFunc
}

func (f *ticket) Resolve(owner platform.Owner) (flowapi.Decision, error) {
	t := f.table
	t.mu.Lock()
	defer t.mu.Unlock()
	if f.closed || f.record.Closing || t.policy == nil {
		return flowapi.Decision{}, ErrStopped
	}
	if f.resolved {
		return f.record.Decision, nil
	}
	if len(owner.Path) > 1024 || len(owner.AppID) > 512 || len(owner.Generation) > 256 {
		return flowapi.Decision{}, errors.New("owner identity too long")
	}
	d, err := t.policy.Decide(owner, f.record.Source.Port(), f.record.Source.Addr().Is6(), t.k.Load()+1)
	if err != nil {
		t.gauges.Rejected++
		return flowapi.Decision{}, err
	}
	c := t.apps[owner.AppID]
	udp := f.record.Protocol == "udp"
	unknown := owner.AppID == ""
	if c.flows >= t.limits.PerApp || (udp && c.udp >= t.limits.UDPPerApp) || (unknown && (t.gauges.Unknown >= t.limits.Unknown || (udp && t.gauges.UnknownUDP >= t.limits.UnknownUDP))) {
		t.gauges.Rejected++
		return flowapi.Decision{}, ErrBudget
	}
	c.flows++
	if udp {
		c.udp++
	}
	t.apps[owner.AppID] = c
	if unknown {
		t.gauges.Unknown++
		if udp {
			t.gauges.UnknownUDP++
		}
	}
	if !udp && t.gauges.TCPBytes+DefaultTCP-MinTCP <= t.limits.TCPBytes {
		t.gauges.TCPBytes += DefaultTCP - MinTCP
		f.tcpBytes = DefaultTCP
		f.receive, f.send = 1<<20, 1<<20
	}
	t.point++
	f.record.Point = t.point
	f.record.Decision = d
	f.record.Owner = owner
	f.resolved = true
	t.k.Add(1)
	t.gauges.Admitted++
	return d, nil
}
func (f *ticket) Buffers() (int, int) {
	t := f.table
	t.mu.Lock()
	defer t.mu.Unlock()
	return f.receive, f.send
}

func (f *ticket) Grow(receive, send int) bool {
	t := f.table
	t.mu.Lock()
	defer t.mu.Unlock()
	if f.closed || !f.resolved || f.record.Protocol != "tcp" || receive < f.receive || send < f.send || receive > 8<<20 || send > 6<<20 {
		return false
	}
	delta := int64(receive-f.receive) + int64(send-f.send)
	if delta > t.limits.TCPBytes-t.gauges.TCPBytes {
		return false
	}
	t.gauges.TCPBytes += delta
	f.tcpBytes += delta
	f.receive, f.send = receive, send
	return true
}
func (f *ticket) Established(source netip.Addr) {
	t := f.table
	t.mu.Lock()
	defer t.mu.Unlock()
	if f.closed {
		return
	}
	f.record.PhysicalSource = source
	if f.handshake {
		t.gauges.Handshakes--
		f.handshake = false
	}
}
func (f *ticket) SetCancel(cancel context.CancelFunc) {
	t := f.table
	t.mu.Lock()
	f.cancel = cancel
	closing := f.closed || f.record.Closing
	t.mu.Unlock()
	if closing {
		cancel()
	}
}
func (f *ticket) Add(up, down uint64) {
	t := f.table
	t.mu.Lock()
	defer t.mu.Unlock()
	if !f.resolved {
		return
	}
	f.record.Up += up
	f.record.Down += down
	a := t.totals.Apps[f.record.Owner.AppID]
	a.Up += up
	a.Down += down
	t.totals.Apps[f.record.Owner.AppID] = a
	l := t.totals.Lines[f.record.Line]
	l.Up += up
	l.Down += down
	t.totals.Lines[f.record.Line] = l
}
func (f *ticket) Close() {
	t := f.table
	t.mu.Lock()
	defer t.mu.Unlock()
	if f.closed {
		return
	}
	f.closed = true
	delete(t.flows, f.record.ID)
	t.gauges.Flows--
	t.gauges.TCPBytes -= f.tcpBytes
	if f.handshake {
		t.gauges.Handshakes--
	}
	udp := f.record.Protocol == "udp"
	if udp {
		t.gauges.UDP--
	}
	if f.resolved {
		app := f.record.Owner.AppID
		c := t.apps[app]
		c.flows--
		if udp {
			c.udp--
		}
		if c.flows == 0 {
			delete(t.apps, app)
		} else {
			t.apps[app] = c
		}
		if app == "" {
			t.gauges.Unknown--
			if udp {
				t.gauges.UnknownUDP--
			}
		}
	}
}
func (t *Table) ReservePending(n int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if n < 0 || int64(n) > t.limits.PendingBytes-t.gauges.PendingBytes {
		return false
	}
	t.gauges.PendingBytes += int64(n)
	return true
}
func (t *Table) ReleasePending(n int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gauges.PendingBytes -= int64(n)
	if t.gauges.PendingBytes < 0 {
		panic("pending byte reservation released twice")
	}
}
func (t *Table) AllowReject(app string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	sec := t.now().Unix()
	if sec != t.rejectSecond {
		t.rejectSecond = sec
		t.rejectTotal = 0
		clear(t.rejectApps)
	}
	if t.rejectTotal >= 5000 || t.rejectApps[app] >= 1000 {
		t.gauges.DroppedNotices++
		return false
	}
	t.rejectTotal++
	t.rejectApps[app]++
	return true
}
func (t *Table) Stats() Gauges { t.mu.Lock(); defer t.mu.Unlock(); return t.gauges }
func (t *Table) Lookup(d time.Duration, err error, owner platform.Owner) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gauges.LookupCount++
	t.gauges.LookupNanoseconds += uint64(max(d, 0))
	if err != nil || owner.AppID == "" {
		t.gauges.LookupMisses++
	}
	if errors.Is(err, platform.ErrAmbiguous) {
		t.gauges.LookupAmbiguous++
	}
}
func (t *Table) Totals() Totals {
	t.mu.Lock()
	defer t.mu.Unlock()
	v := Totals{Apps: map[string]Bytes{}, Lines: map[string]Bytes{}}
	for k, b := range t.totals.Apps {
		v.Apps[k] = b
	}
	for k, b := range t.totals.Lines {
		v.Lines[k] = b
	}
	return v
}

type Selector struct {
	IDs         []uint64   `json:"ids,omitempty"`
	Line        string     `json:"line,omitempty"`
	App         string     `json:"app,omitempty"`
	NotLine     string     `json:"notLine,omitempty"`
	Source      netip.Addr `json:"source,omitempty"`
	IPv6        bool       `json:"ipv6,omitempty"`
	OutsideOnly bool       `json:"outsideOnly,omitempty"`
}
type CloseResult struct {
	Closed int `json:"closed"`
	Failed int `json:"failed"`
	Gone   int `json:"gone"`
}

func (s Selector) Validate() error {
	if s.OutsideOnly {
		return errors.New("outside connections are handled by Control")
	}
	n := 0
	if len(s.IDs) > 0 {
		n++
	}
	if s.Line != "" {
		n++
	}
	if s.App != "" && s.NotLine != "" {
		n++
	}
	if s.Source.IsValid() {
		n++
	}
	if s.IPv6 {
		n++
	}
	if n != 1 {
		return errors.New("select exactly one closure condition")
	}
	return nil
}
func (t *Table) CloseFlows(s Selector, before uint64) (CloseResult, error) {
	if err := s.Validate(); err != nil {
		return CloseResult{}, err
	}
	t.mu.Lock()
	if s.App != "" && t.policy != nil && t.policy.Predict(s.App).Distribution != nil {
		t.mu.Unlock()
		return CloseResult{}, errors.New("shared apps reconnect only outside connections through Control")
	}
	ids := map[uint64]bool{}
	for _, id := range s.IDs {
		ids[id] = true
	}
	var cancels []context.CancelFunc
	result := CloseResult{}
	for id, f := range t.flows {
		r := f.record
		match := ids[id] || (s.Line != "" && r.Line == s.Line) || (s.App != "" && r.Owner.AppID == s.App && r.Line != s.NotLine) || (s.Source.IsValid() && r.PhysicalSource == s.Source) || (s.IPv6 && r.Source.Addr().Is6())
		if !match {
			continue
		}
		delete(ids, id)
		if before != 0 && r.Point >= before {
			continue
		}
		if r.Closing {
			continue
		}
		f.record.Closing = true
		result.Closed++
		if f.cancel != nil {
			cancels = append(cancels, f.cancel)
		}
	}
	result.Gone = len(ids)
	t.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	return result, nil
}
func (t *Table) CloseAll() {
	t.mu.Lock()
	var callbacks []context.CancelFunc
	for _, f := range t.flows {
		f.record.Closing = true
		if f.cancel != nil {
			callbacks = append(callbacks, f.cancel)
		}
	}
	t.mu.Unlock()
	for _, cancel := range callbacks {
		cancel()
	}
}
func sorted(records []Record) {
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
}
