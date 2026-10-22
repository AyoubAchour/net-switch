package nsengine

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/tests/linux/engine"
)

// Session is one attached control session: the instance it attached to and
// the epoch the engine handed out. Every command carries both.
type Session struct {
	d        *Driver
	instance string
	epoch    uint64

	mu        sync.Mutex
	stopRenew context.CancelFunc
}

var _ engine.Controller = (*Session)(nil)

// RenewEvery is how often an auto-renewing session renews its 30 s lease.
const RenewEvery = 5 * time.Second

// InstanceID implements engine.Controller.
func (s *Session) InstanceID() string { return s.instance }

// Epoch implements engine.Controller.
func (s *Session) Epoch() uint64 { return s.epoch }

func (s *Session) request(method string) protocol.Request {
	return protocol.Request{ID: s.d.id(method), Method: method, Instance: s.instance, Epoch: s.epoch}
}

// Renew implements engine.Controller.
func (s *Session) Renew(ctx context.Context) error {
	return s.d.do(ctx, s.request("renew"), nil)
}

// SetAutoRenew implements engine.Controller.
func (s *Session) SetAutoRenew(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopRenew != nil {
		s.stopRenew()
		s.stopRenew = nil
	}
	if !on {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.stopRenew = cancel
	go func() {
		tick := time.NewTicker(RenewEvery)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				// A failed renewal shows up as the lapse a case checks for.
				_ = s.Renew(ctx)
			}
		}
	}()
}

// renewing reports whether the session renews itself.
func (s *Session) renewing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopRenew != nil
}

// Start implements engine.Controller.
func (s *Session) Start(ctx context.Context, n uint64, cfg engine.Config) (engine.Applied, error) {
	return s.revision(ctx, "start", n, cfg)
}

// Apply implements engine.Controller.
func (s *Session) Apply(ctx context.Context, n uint64, cfg engine.Config) (engine.Applied, error) {
	return s.revision(ctx, "apply", n, cfg)
}

func (s *Session) revision(ctx context.Context, method string, n uint64, cfg engine.Config) (engine.Applied, error) {
	rev, err := s.d.revision(ctx, n, cfg)
	if err != nil {
		return engine.Applied{}, err
	}
	req := s.request(method)
	req.Revision = &rev
	var a policy.Applied
	if err := s.d.do(ctx, req, &a); err != nil {
		return engine.Applied{}, err
	}
	return applied(a), nil
}

// Stop implements engine.Controller.
func (s *Session) Stop(ctx context.Context) error {
	var stopped bool
	if err := s.d.do(ctx, s.request("stop"), &stopped); err != nil {
		return err
	}
	if !stopped {
		return fmt.Errorf("stop: the engine didn't confirm it stopped")
	}
	return nil
}

// Flows implements engine.Controller.
func (s *Session) Flows(ctx context.Context, cursor string) (engine.FlowPage, error) {
	req := s.request("flows")
	req.Cursor = cursor
	var page flows.Page
	if err := s.d.do(ctx, req, &page); err != nil {
		return engine.FlowPage{}, err
	}
	out := engine.FlowPage{Next: page.Cursor, Flows: make([]engine.Flow, 0, len(page.Flows))}
	for _, r := range page.Flows {
		out.Flows = append(out.Flows, flow(r))
	}
	return out, nil
}

// Totals implements engine.Controller.
func (s *Session) Totals(ctx context.Context) (engine.Totals, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out := engine.Totals{PerApp: map[string]engine.Bytes{}, PerLine: map[engine.LineID]engine.Bytes{}, AppGenerations: map[string]string{}, LineGenerations: map[engine.LineID]string{}}
	req := s.request("totals")
	seen := map[string]bool{}
	count := -1
	receipt := ""
	for {
		var page flows.TotalsPage
		if err := s.d.do(ctx, req, &page); err != nil {
			return engine.Totals{}, err
		}
		if page.Instance != s.instance {
			return engine.Totals{}, fmt.Errorf("totals crossed an engine restart")
		}
		if count < 0 {
			count = page.Count
			receipt = page.Receipt
		}
		if page.Count != count || receipt == "" || page.Receipt != receipt {
			return engine.Totals{}, fmt.Errorf("totals snapshot count changed")
		}
		for app, b := range page.Apps {
			if _, exists := out.PerApp[app]; exists {
				return engine.Totals{}, fmt.Errorf("duplicate totals app")
			}
			out.PerApp[app] = engine.Bytes{Up: int64(b.Up), Down: int64(b.Down)}
			out.AppGenerations[app] = b.Generation
		}
		for line, b := range page.Lines {
			if _, exists := out.PerLine[engine.LineID(line)]; exists {
				return engine.Totals{}, fmt.Errorf("duplicate totals line")
			}
			out.PerLine[engine.LineID(line)] = engine.Bytes{Up: int64(b.Up), Down: int64(b.Down)}
			out.LineGenerations[engine.LineID(line)] = b.Generation
		}
		if page.Cursor == "" {
			if len(out.PerApp)+len(out.PerLine) != count {
				return engine.Totals{}, fmt.Errorf("incomplete totals snapshot")
			}
			ack := s.request("ackTotals")
			ack.Receipt, ack.OpID = receipt, "ack-"+receipt
			if err := s.d.do(ctx, ack, nil); err != nil {
				return engine.Totals{}, err
			}
			break
		}
		if seen[page.Cursor] || len(page.Apps)+len(page.Lines) == 0 {
			return engine.Totals{}, fmt.Errorf("totals cursor made no progress")
		}
		seen[page.Cursor], req.Cursor = true, page.Cursor
	}
	return out, nil
}

// CloseFlows implements engine.Controller. The selector goes as the case
// gives it, an empty one included: refusing it is the engine's job.
func (s *Session) CloseFlows(ctx context.Context, opID string, sel engine.Selector, startedBefore uint64) (engine.CloseResult, error) {
	wire, err := selector(sel)
	if err != nil {
		return engine.CloseResult{}, err
	}
	req := s.request("closeFlows")
	req.OpID, req.Selector, req.StartedBefore = opID, wire, startedBefore
	var r flows.CloseResult
	if err := s.d.do(ctx, req, &r); err != nil {
		return engine.CloseResult{}, err
	}
	return engine.CloseResult{Closed: r.Closed, Failed: r.Failed, Gone: r.Gone}, nil
}

// Probe implements engine.Controller.
func (s *Session) Probe(ctx context.Context, opID string, line engine.LineID, operator string) (engine.ProbeResult, error) {
	req := s.request("probe")
	req.OpID, req.Line, req.Operator = opID, string(line), operator
	var r platform.ProbeResult
	if err := s.d.do(ctx, req, &r); err != nil {
		return engine.ProbeResult{}, err
	}
	return engine.ProbeResult{OK: r.OK, Latency: r.Latency, Error: r.Error}, nil
}

// Predict implements engine.Controller.
func (s *Session) Predict(ctx context.Context, app engine.App) (engine.Prediction, error) {
	req := s.request("predict")
	req.App = app.Key()
	var p policy.Prediction
	if err := s.d.do(ctx, req, &p); err != nil {
		return engine.Prediction{}, err
	}
	out := engine.Prediction{Line: engine.LineID(p.Line), Blocked: p.Blocked}
	if p.Distribution != nil {
		out.Distribution = map[engine.LineID]float64{}
		for line, share := range p.Distribution {
			out.Distribution[engine.LineID(line)] = share
		}
	}
	return out, nil
}

// Stats implements engine.Controller.
func (s *Session) Stats(ctx context.Context) (engine.Stats, error) {
	var raw json.RawMessage
	if err := s.d.do(ctx, s.request("stats"), &raw); err != nil {
		return engine.Stats{}, err
	}
	return decodeStats(raw)
}

// InjectFault requires the live engine's acknowledgement. Production binaries
// reject these commands; the acceptance workflow builds with -tags acceptance.
func (s *Session) InjectFault(ctx context.Context, f engine.Fault) (engine.FaultAck, error) {
	r := s.request("testFault")
	r.Fault, _ = json.Marshal(f)
	var ack engine.FaultAck
	err := s.d.do(ctx, r, &ack)
	return ack, err
}

// --- translations between the suite's types and main's -------------------

// shareScale turns the suite's fractional combining shares into the integer
// weights a revision carries.
const shareScale = 1 << 20

// wireConfig is cfg as a revision carries it, with each line's addresses.
func wireConfig(cfg engine.Config, lines []platform.Line) policy.Config {
	c := policy.Config{Lines: lines, Combine: cfg.Policy.Combine, IPv6: cfg.Policy.IPv6}
	if len(cfg.Policy.Pins) > 0 {
		c.AppLines = map[string]string{}
		for _, pin := range cfg.Policy.Pins {
			c.AppLines[pin.App.Key()] = string(pin.Line)
		}
	}
	if len(cfg.Policy.Shares) > 0 {
		c.Shares = map[string]uint64{}
		for id, share := range cfg.Policy.Shares {
			c.Shares[string(id)] = uint64(math.Round(share * shareScale))
		}
	}
	if len(cfg.Lanes) > 0 {
		c.Lanes = map[string]string{}
		for lane, target := range cfg.Lanes {
			c.Lanes[string(lane)] = string(target)
		}
	}
	for _, id := range cfg.Policy.Blocked {
		c.Blocked = append(c.Blocked, string(id))
	}
	return c
}

// revision is revision n of cfg, hashed as the engine checks it.
func (d *Driver) revision(ctx context.Context, n uint64, cfg engine.Config) (policy.Revision, error) {
	lines := make([]platform.Line, 0, len(cfg.Lines))
	for _, l := range cfg.Lines {
		addrs, err := d.addresses(ctx, d.env.Netns, l.Interface)
		if err != nil {
			return policy.Revision{}, fmt.Errorf("line %s's addresses: %w", l.ID, err)
		}
		lines = append(lines, platform.Line{ID: string(l.ID), Interface: l.Interface, Addresses: addrs})
	}
	c := wireConfig(cfg, lines)
	return policy.Revision{N: n, Hash: policy.Hash(c), Config: c}, nil
}

func applied(a policy.Applied) engine.Applied {
	return engine.Applied{Revision: engine.Revision{N: a.N, Hash: a.Hash}, Point: a.Point}
}

func flow(r flows.Record) engine.Flow {
	return engine.Flow{
		ID:          strconv.FormatUint(r.ID, 10),
		App:         r.Owner.Path,
		AppID:       r.Owner.AppID,
		PID:         int(r.Owner.PID),
		Protocol:    r.Protocol,
		Source:      r.Source,
		Destination: r.Destination,
		Lane:        engine.LineID(r.Lane),
		Line:        engine.LineID(r.Line),
		Revision:    r.Revision,
		Epoch:       r.Epoch,
		Point:       r.Point,
		Started:     r.Start,
		Up:          int64(r.Up),
		Down:        int64(r.Down),
	}
}

func selector(sel engine.Selector) (flows.Selector, error) {
	out := flows.Selector{Line: string(sel.Line), App: sel.App, NotLine: string(sel.NotLine)}
	for _, id := range sel.IDs {
		n, err := strconv.ParseUint(id, 10, 64)
		if err != nil {
			return flows.Selector{}, fmt.Errorf("flow id %q isn't one of 1.0's: %w", id, err)
		}
		out.IDs = append(out.IDs, n)
	}
	return out, nil
}

// decodeStats reads stats' result: {"engine": ..., "eventsDropped": n}. The
// engine's runtime nests the flow table's gauges under "flows" beside its own
// counters; a bare flow table sends the gauges themselves.
func decodeStats(raw []byte) (engine.Stats, error) {
	var top struct {
		Engine        json.RawMessage `json:"engine"`
		EventsDropped uint64          `json:"eventsDropped"`
	}
	if err := json.Unmarshal(raw, &top); err != nil {
		return engine.Stats{}, fmt.Errorf("stats: %w", err)
	}
	gauges := top.Engine
	counters := map[string]uint64{}
	var nested map[string]json.RawMessage
	if json.Unmarshal(top.Engine, &nested) == nil {
		if f, ok := nested["flows"]; ok {
			gauges = f
			for name, value := range nested {
				var n uint64
				if name != "flows" && json.Unmarshal(value, &n) == nil {
					counters[name] = n
				}
			}
		}
	}
	var g flows.Gauges
	if err := json.Unmarshal(gauges, &g); err != nil {
		return engine.Stats{}, fmt.Errorf("stats gauges: %w", err)
	}
	return engine.Stats{
		RefusedTCP: g.RefusedTCP, RefusedUDP: g.RefusedUDP,
		PeakUnknown: g.PeakUnknown, PeakUnknownUDP: g.PeakUnknownUDP,
		AdmittedUnknown: g.AdmittedUnknown, AdmittedUnknownUDP: g.AdmittedUnknownUDP,
		OwnerLookup: nested["ownerLookup"],
		TunKernel:   nested["tunKernel"],
		TCPFlows:    nested["tcpFlows"],
		PeakFlows:   g.PeakFlows, PeakHandshakes: g.PeakHandshakes, PeakUDP: g.PeakUDP, PeakPerApp: g.PeakPerApp, PeakUDPPerApp: g.PeakUDPPerApp,
		Flows: int64(g.Flows), Handshakes: int64(g.Handshakes), UDP: int64(g.UDP),
		Unknown: int64(g.Unknown), UnknownUDP: int64(g.UnknownUDP), TimeWait: int64(g.TimeWait),
		TCPBytes: g.TCPBytes, PendingBytes: g.PendingBytes, SnapshotBytes: g.SnapshotBytes,
		PendingPeakBytes: g.PendingPeakBytes,
		UDPReadBytes:     g.UDPReadBytes,
		UDPReplyBytes:    g.UDPReplyBytes, UDPReplyPeakBytes: g.UDPReplyPeakBytes,
		UDPAdapterBytes: g.UDPAdapterBytes,
		Admitted:        g.Admitted, Rejected: g.Rejected, DroppedNotices: g.DroppedNotices, TimeWaitSkipped: g.TimeWaitSkipped,
		EventsDropped: top.EventsDropped + g.EventsDropped,
		LookupCount:   g.LookupCount, LookupMisses: g.LookupMisses, LookupAmbiguous: g.LookupAmbiguous,
		LookupTime:      time.Duration(g.LookupNanoseconds),
		LookupHistogram: g.LookupHistogram,
		Counters:        counters,
	}, nil
}
