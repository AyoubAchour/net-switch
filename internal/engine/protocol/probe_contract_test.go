package protocol

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

type configuredProbe struct {
	probeFake
	request platform.ProbeRequest
	line    string
	count   int
}

func (p *configuredProbe) ProbeConfigured(_ context.Context, line string, r platform.ProbeRequest) (platform.ProbeResult, error) {
	p.request, p.line = r, line
	p.count++
	ms := 23.5
	return platform.ProbeResult{OK: true, Kind: "quick", LatencyMS: &ms, Outcome: "ok"}, nil
}

func TestConfiguredProbeFieldsAreFencedAndIdempotent(t *testing.T) {
	s, _, request := setup(t)
	p := &configuredProbe{}
	s.prober = p
	r := request("probe")
	r.OpID = "custom"
	r.Line = "A"
	r.Target = "192.0.2.1:8443"
	r.Custom = true
	r.Quick = true
	wire, err := json.Marshal(call(t, s, r))
	if err != nil || !strings.Contains(string(wire), `"kind":"quick"`) || !strings.Contains(string(wire), `"latencyMs":23.5`) || strings.Contains(string(wire), `"latency":`) {
		t.Fatal("protocol changed probe kind or latency units", string(wire), err)
	}
	call(t, s, r)
	if p.count != 1 || p.line != "A" || p.request != (platform.ProbeRequest{Target: r.Target, Quick: true, Custom: true}) {
		t.Fatal(p)
	}
	r.Quick = false
	if s.Handle(context.Background(), r).Error == "" || p.count != 1 {
		t.Fatal("changed probe reused operation ID")
	}
	r.OpID = "stale"
	r.Epoch = 0
	if s.Handle(context.Background(), r).Error == "" || p.count != 1 {
		t.Fatal("unfenced probe executed")
	}
}
