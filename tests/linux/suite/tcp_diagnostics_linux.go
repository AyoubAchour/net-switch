//go:build linux

package suite

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/engine"
)

// Keep diagnostics outside the engine's data path. The ordinary release build
// reports bounded snapshots of existing TCP endpoint counters; the harness
// samples all namespace hops at wave boundaries and after an RTO.
type tcpDiagnostics struct {
	enc               *json.Encoder
	previousRTO       uint64
	lastFlow, lastHop time.Time
	previousWave      int
}

func newTCPDiagnostics(e *Env) *tcpDiagnostics {
	f, err := os.Create(filepath.Join(e.T.Dir(), "tcp-loss.jsonl"))
	e.T.Require(err == nil, "create TCP loss diagnostics (%v)", err)
	d := &tcpDiagnostics{enc: json.NewEncoder(f), previousWave: -1}
	e.T.Cleanup(func() { e.T.Check(f.Close() == nil, "close TCP loss diagnostics") })
	d.hops(e, "before downloads")
	return d
}

func (d *tcpDiagnostics) write(e *Env, value any) {
	e.T.Require(d.enc.Encode(value) == nil, "record TCP loss diagnostics")
}

func (d *tcpDiagnostics) hops(e *Env, reason string) {
	ctx, cancel := context.WithTimeout(e.Ctx(), 5*time.Second)
	defer cancel()
	snapshot, err := e.Net.Traffic(ctx)
	d.write(e, struct {
		Reason  string
		Network any
	}{reason, snapshot})
	// A missing observation must be visible, but must not replace the demand
	// or budget verdict if that independently fails later in this case.
	e.T.Check(err == nil, "collect all TCP hops (%s; %v)", reason, err)
	d.lastHop = time.Now()
}

func (d *tcpDiagnostics) sample(e *Env, st engine.Stats, elapsed time.Duration, burstMS int, final bool) {
	now := time.Now()
	rto := st.Counters["tcpRTOs"]
	wave := int(elapsed.Milliseconds()) / burstMS
	changed := rto != d.previousRTO
	if changed || final || now.Sub(d.lastFlow) >= time.Second {
		d.write(e, struct {
			At        time.Time
			ElapsedMS int64
			Final     bool
			Flows     json.RawMessage
			Counters  map[string]uint64
			TunKernel json.RawMessage
		}{now.UTC(), elapsed.Milliseconds(), final, st.TCPFlows, st.Counters, st.TunKernel})
		d.lastFlow = now
	}
	if changed {
		e.T.Logf("TCP RTO %d -> %d at %s: app-leg counters and native socket tuples in tcp-loss.jsonl", d.previousRTO, rto, elapsed)
	}
	if final {
		var flows []json.RawMessage
		err := json.Unmarshal(st.TCPFlows, &flows)
		e.T.Check(err == nil && len(flows) >= 64 && st.Counters["tcpFlowsOmitted"] == 0,
			"every held download has app-leg TCP diagnostics (%d endpoints, %d omitted, %v)", len(flows), st.Counters["tcpFlowsOmitted"], err)
	}
	// All RTOs remain in the per-flow samples. Coalesce network snapshots to
	// at most one per second if several endpoints time out together.
	if final || wave != d.previousWave || (rto != d.previousRTO && now.Sub(d.lastHop) >= time.Second) {
		reason := "wave boundary"
		if final {
			reason = "all downloads held, before release"
		} else if changed {
			reason = "RTO observed"
		}
		d.hops(e, reason)
		d.previousWave = wave
		d.previousRTO = rto
	}
}
