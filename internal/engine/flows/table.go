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
	PeakFlows, PeakHandshakes, PeakUDP, PeakPerApp, PeakUDPPerApp int
	PendingPeakBytes                                              int64
	// Non-cumulative buckets: 100 us wide through 20 ms, then overflow.
	// Histograms can be subtracted across a cold-socket test phase.
	LookupHistogram                                                                                   [201]uint64
	UDPReadBytes                                                                                      int64
	DoubleReleases                                                                                    uint64
	TimeWait                                                                                          int
	TimeWaitSkipped                                                                                   uint64
	ClosingOverflow, ClosingOverflowPeak                                                              int
	EventsDropped                                                                                     uint64
	Flows, Handshakes, UDP, Unknown, UnknownUDP                                                       int
	TCPBytes, PendingBytes, SnapshotBytes                                                             int64
	Rejected, DroppedNotices, Admitted, LookupCount, LookupMisses, LookupAmbiguous, LookupNanoseconds uint64
}
type counts struct{ flows, udp int }
type Table struct {
	applyMu              sync.Mutex
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
	timeWaitLogSecond    int64
	rejectTotal          int
	rejectApps           map[string]int
	events               chan flowapi.Event
	eventsDropped        atomic.Uint64
	pendingBytes         atomic.Int64
	pendingPeakBytes     atomic.Int64
	doubleReleases       atomic.Uint64
}

func New(l Limits, store StateStore) *Table {
	return &Table{limits: l, now: time.Now, store: store, flows: map[uint64]*ticket{}, apps: map[string]counts{}, totals: Totals{Apps: map[string]Bytes{}, Lines: map[string]Bytes{}}, snapshots: map[uint64]*snapshot{}, rejectApps: map[string]int{}, events: make(chan flowapi.Event, 64)}
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
	t.applyMu.Lock()
	defer t.applyMu.Unlock()
	t.mu.Lock()
	if t.applied != nil {
		if r.N < t.applied.N {
			t.mu.Unlock()
			return policy.Applied{}, ErrStale
		}
		if r.N == t.applied.N {
			if r.Hash != t.applied.Hash {
				t.mu.Unlock()
				return policy.Applied{}, ErrConflict
			}
			a := *t.applied
			t.mu.Unlock()
			return a, nil
		}
	}
	t.mu.Unlock()
	// Only revision history is durable. The apply point belongs to this live
	// instance and is assigned after persistence, alongside the policy swap.
	a := policy.Applied{N: r.N, Hash: r.Hash}
	if t.store != nil {
		if err := t.store.SaveApplied(a); err != nil {
			return policy.Applied{}, err
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.point++
	a.Point = t.point
	t.policy = p
	t.applied = &a
	return a, nil
}
func (t *Table) Unload() {
	t.applyMu.Lock()
	defer t.applyMu.Unlock()
	t.mu.Lock()
	t.policy = nil
	t.applied = nil
	t.mu.Unlock()
}
func (t *Table) Predict(app string) (policy.Prediction, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.policy == nil {
		return policy.Prediction{}, ErrStopped
	}
	return t.policy.Predict(app), nil
}

func (t *Table) EchoLine(ipv6 bool) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.policy == nil {
		return "", ErrStopped
	}
	d, err := t.policy.Decide(platform.Owner{}, 0, ipv6, 0)
	return d.Line, err
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
	if tuple.Source.Addr().Is6() && !t.policy.IPv6() {
		t.gauges.Rejected++
		return nil, policy.ErrIPv6
	}
	if t.gauges.Flows >= t.limits.Flows || (protocol == "udp" && t.gauges.UDP >= t.limits.UDP) || (protocol == "tcp" && t.gauges.Handshakes >= t.limits.Handshakes) {
		t.gauges.Rejected++
		return nil, ErrBudget
	}
	t.nextID++
	f := &ticket{table: t, record: Record{ID: t.nextID, Epoch: t.epoch, Start: t.now(), Protocol: protocol, Source: tuple.Source, Destination: tuple.Destination}}
	t.gauges.Flows++
	t.gauges.PeakFlows = max(t.gauges.PeakFlows, t.gauges.Flows)
	if protocol == "udp" {
		t.gauges.UDP++
		t.gauges.PeakUDP = max(t.gauges.PeakUDP, t.gauges.UDP)
		t.gauges.UDPReadBytes += flowapi.UDPReadBuffer + flowapi.UDPAdapterBuffer
	} else {
		f.handshake = true
		f.receive, f.send = 64<<10, 64<<10
		t.gauges.Handshakes++
		t.gauges.PeakHandshakes = max(t.gauges.PeakHandshakes, t.gauges.Handshakes)
	}
	t.flows[f.record.ID] = f
	return f, nil
}

type ticket struct {
	accountMu                           sync.RWMutex
	accountClosed                       bool
	up, down                            atomic.Uint64
	retired, timeWait, timeWaitReserved bool
	closingOverflow                     bool
	lineAddresses                       []netip.Addr
	table                               *Table
	record                              Record
	resolved, closed, handshake         bool
	tcpBytes                            int64
	receive, send                       int
	cancel                              context.CancelFunc
}

func (f *ticket) Resolve(owner platform.Owner) (flowapi.Decision, error) {
	t := f.table
	t.mu.Lock()
	defer t.mu.Unlock()
	if f.closed || f.retired || f.record.Closing || t.policy == nil {
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
	t.gauges.PeakPerApp = max(t.gauges.PeakPerApp, c.flows)
	if udp {
		c.udp++
		t.gauges.PeakUDPPerApp = max(t.gauges.PeakUDPPerApp, c.udp)
	}
	t.apps[owner.AppID] = c
	if unknown {
		t.gauges.Unknown++
		if udp {
			t.gauges.UnknownUDP++
		}
	}
	t.point++
	f.record.Point = t.point
	f.record.Decision = d
	f.record.Owner = owner
	f.lineAddresses = t.policy.Addresses(d.Line)
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
	if f.closed || f.retired || !f.resolved || f.record.Protocol != "tcp" || receive < f.receive || send < f.send || receive > 8<<20 || send > 6<<20 {
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

// Shrink releases growth only after the relay has reduced both socket limits.
// The floor is count-admitted; only bytes above it consume the shared budget.
func (f *ticket) Shrink(receive, send int) {
	t := f.table
	t.mu.Lock()
	defer t.mu.Unlock()
	if f.closed || receive < MinTCP || send < MinTCP || receive > f.receive || send > f.send {
		return
	}
	delta := int64(f.receive-receive) + int64(f.send-send)
	f.receive, f.send = receive, send
	f.tcpBytes -= delta
	t.gauges.TCPBytes -= delta
}

// TimeWait exchanges live admission for a retained-endpoint slot. This includes
// payload-free LAST_ACK/CLOSING endpoints as well as TIME_WAIT. A transition
// between these states keeps the same reservation.
// False skips TIME_WAIT; it cannot reject a new flow.
func (f *ticket) TimeWait() bool {
	return f.retain(false)
}

// Closing counts FIN-only overflow until removal or entry into TIME_WAIT.
// The forwarder's sweep grants it one second for the FIN to be acknowledged.
func (f *ticket) Closing() bool {
	return f.retain(true)
}

func (f *ticket) retain(closing bool) bool {
	t := f.table
	t.mu.Lock()
	defer t.mu.Unlock()
	if !closing {
		f.endOverflowLocked()
	}
	if f.closed || f.timeWait {
		return f.timeWaitReserved
	}
	f.timeWait = true
	f.retireLocked()
	if t.gauges.TimeWait >= t.limits.TimeWait {
		t.gauges.TimeWaitSkipped++
		if closing {
			f.closingOverflow = true
			t.gauges.ClosingOverflow++
			t.gauges.ClosingOverflowPeak = max(t.gauges.ClosingOverflowPeak, t.gauges.ClosingOverflow)
		}
		second := t.now().Unix()
		if t.gauges.TimeWaitSkipped == 1 || second != t.timeWaitLogSecond {
			t.timeWaitLogSecond = second
			t.Emit(flowapi.Event{Type: "log", Message: "retained TCP endpoint cap reached; skipping TIME_WAIT, allowing FIN ACKs one second before reset", App: f.record.Owner.AppID})
		}
		return false
	}
	f.timeWaitReserved = true
	t.gauges.TimeWait++
	return true
}

// EndTimeWait releases the endpoint slot on removal, not on the next sweep.
func (f *ticket) EndTimeWait() {
	f.table.mu.Lock()
	defer f.table.mu.Unlock()
	f.endTimeWaitLocked()
}

func (f *ticket) endTimeWaitLocked() {
	f.endOverflowLocked()
	if f.timeWaitReserved {
		f.timeWaitReserved = false
		f.table.gauges.TimeWait--
	}
}

func (f *ticket) endOverflowLocked() {
	if f.closingOverflow {
		f.closingOverflow = false
		f.table.gauges.ClosingOverflow--
	}
}

// Retire frees admission immediately while the relay finishes its last byte
// accounting. Close folds those bytes and releases memory once the relay ends.
func (f *ticket) Retire() {
	f.table.mu.Lock()
	defer f.table.mu.Unlock()
	f.retireLocked()
}

func (f *ticket) retireLocked() {
	if f.retired {
		return
	}
	f.retired = true
	t := f.table
	t.gauges.Flows--
	if f.handshake {
		t.gauges.Handshakes--
		f.handshake = false
	}
	udp := f.record.Protocol == "udp"
	if udp {
		t.gauges.UDP--
		t.gauges.UDPReadBytes -= flowapi.UDPReadBuffer + flowapi.UDPAdapterBuffer
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
	// The per-ticket gate makes close's final fold atomic with respect to a
	// concurrent UDP completion, without taking the packet-path table lock.
	f.accountMu.RLock()
	defer f.accountMu.RUnlock()
	if f.accountClosed {
		return
	}
	f.up.Add(up)
	f.down.Add(down)
}
func (f *ticket) Close() {
	t := f.table
	t.mu.Lock()
	defer t.mu.Unlock()
	if f.closed {
		return
	}
	f.closed = true
	f.endTimeWaitLocked()
	f.retireLocked()
	delete(t.flows, f.record.ID)
	t.gauges.TCPBytes -= f.tcpBytes
	if f.resolved {
		f.accountMu.Lock()
		f.accountClosed = true
		fold(t.totals.Apps, f.record.Owner.AppID, f.up.Load(), f.down.Load())
		fold(t.totals.Lines, f.record.Line, f.up.Load(), f.down.Load())
		f.accountMu.Unlock()
	}
}
func (t *Table) ReservePending(n int) bool {
	for {
		old := t.pendingBytes.Load()
		if n < 0 || int64(n) > t.limits.PendingBytes-old {
			return false
		}
		if t.pendingBytes.CompareAndSwap(old, old+int64(n)) {
			for peak := t.pendingPeakBytes.Load(); old+int64(n) > peak && !t.pendingPeakBytes.CompareAndSwap(peak, old+int64(n)); peak = t.pendingPeakBytes.Load() {
			}
			return true
		}
	}
}
func (t *Table) ReleasePending(n int) {
	for {
		old := t.pendingBytes.Load()
		if n < 0 || int64(n) > old {
			t.doubleReleases.Add(1)
			t.Emit(flowapi.Event{Type: "log", Message: "invalid pending byte release (possible double release)"})
			return
		}
		if t.pendingBytes.CompareAndSwap(old, old-int64(n)) {
			return
		}
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
	t.Emit(flowapi.Event{Type: "log", Message: "flow rejected", App: app})
	return true
}
func (t *Table) Stats() Gauges {
	t.mu.Lock()
	defer t.mu.Unlock()
	g := t.gauges
	g.PendingBytes = t.pendingBytes.Load()
	g.PendingPeakBytes = t.pendingPeakBytes.Load()
	g.DoubleReleases = t.doubleReleases.Load()
	g.EventsDropped = t.eventsDropped.Load()
	return g
}

func (t *Table) Events() <-chan flowapi.Event { return t.events }

// No control lock or reader is allowed on the forwarding path.
func (t *Table) Emit(event flowapi.Event) {
	if len(event.Message) > 4096 {
		event.Message = event.Message[:4096]
	}
	select {
	case t.events <- event:
	default:
		t.eventsDropped.Add(1)
	}
}

func (t *Table) LineError(line string, err error) {
	t.Emit(flowapi.Event{Type: "lineError", Line: line, Message: err.Error()})
}
func (t *Table) Lookup(d time.Duration, err error, owner platform.Owner) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gauges.LookupCount++
	t.gauges.LookupNanoseconds += uint64(max(d, 0))
	t.gauges.LookupHistogram[min(int(max(d, 0)/(100*time.Microsecond)), 200)]++
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
	for _, f := range t.flows {
		if f.resolved {
			up, down := f.up.Load(), f.down.Load()
			fold(v.Apps, f.record.Owner.AppID, up, down)
			fold(v.Lines, f.record.Line, up, down)
		}
	}
	return v
}

func fold(m map[string]Bytes, key string, up, down uint64) {
	b := m[key]
	b.Up += up
	b.Down += down
	m[key] = b
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
	if (s.App == "") != (s.NotLine == "") {
		return errors.New("reconnect requires both app and notLine")
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
		if f.retired {
			continue
		}
		r := f.record
		match := ids[id] || (s.Line != "" && r.Line == s.Line) || (s.App != "" && r.Owner.AppID == s.App && r.Line != s.NotLine) || f.matchesSource(s.Source) || (s.IPv6 && r.Source.Addr().Is6())
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
		if f.retired {
			continue
		}
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
func (f *ticket) matchesSource(source netip.Addr) bool {
	if !source.IsValid() {
		return false
	}
	if f.record.PhysicalSource == source {
		return true
	}
	// A device-bound wildcard UDP socket lets the OS choose its source for
	// each destination. Retire this line's same-family mappings, using the
	// addresses saved at admission even after policy replacement.
	if f.record.Protocol != "udp" || !f.record.PhysicalSource.IsUnspecified() || f.record.Source.Addr().Is6() != source.Is6() {
		return false
	}
	for _, a := range f.lineAddresses {
		if a == source {
			return true
		}
	}
	return false
}

func sorted(records []Record) {
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
}
