//go:build linux

package suite

import (
	"context"
	"io"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/tests/linux/engine"
	"github.com/AyoubAchour/net-switch/tests/linux/harness"
)

func TestCapacityShortfallNeedsCompleteRefusalEvidence(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*engine.Stats, *int)
		fail bool
	}{
		{"proved unknown overflow", func(*engine.Stats, *int) {}, false},
		{"repeated cap refusals cannot hide a gap", func(s *engine.Stats, _ *int) {
			s.RefusedTCP.Total = 70
			s.Counters["tcpRejected"] = 80
		}, true},
		{"handshake refusal", func(s *engine.Stats, _ *int) { s.RefusedTCP.Total--; s.RefusedTCP.Handshakes++ }, true},
		{"policy refusal", func(s *engine.Stats, _ *int) { s.RefusedTCP.Total--; s.RefusedTCP.Policy++ }, true},
		{"unexplained refusal", func(s *engine.Stats, _ *int) { s.RefusedTCP.Total--; s.RefusedTCP.Unexplained++ }, true},
		{"other app cap", func(s *engine.Stats, _ *int) { s.RefusedTCP.Total--; s.RefusedTCP.PerApp++ }, true},
		{"outbound failure", func(s *engine.Stats, _ *int) { s.Counters["tcpDialFailed"] = 1 }, true},
		{"lost admitted flow", func(s *engine.Stats, _ *int) { s.Admitted++ }, true},
		{"client timeout", func(_ *engine.Stats, refused *int) { *refused = *refused - 1 }, true},
		{"missing forwarding decision", func(s *engine.Stats, _ *int) { s.Counters["tcpRejected"]++ }, true},
		{"unclassified lookup miss", func(s *engine.Stats, _ *int) { s.LookupMisses++ }, true},
		{"memory exceeded", func(s *engine.Stats, _ *int) { s.Counters["runtimeBytes"] = 513 << 20 }, true},
		{"memory missing", func(s *engine.Stats, _ *int) { delete(s.Counters, "runtimeBytes") }, true},
		{"unknown pool exceeded", func(s *engine.Stats, _ *int) { s.PeakUnknown = 2049 }, true},
		{"per-app cap exceeded", func(s *engine.Stats, _ *int) { s.PeakPerApp = 8193 }, true},
		{"total cap exceeded", func(s *engine.Stats, _ *int) { s.PeakFlows = 65537 }, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := engine.Stats{
				Admitted: 90, LookupMisses: 10, RefusedTCP: flows.Refusals{Total: 50, Unknown: 10},
				Counters: map[string]uint64{"tcpRejected": 60, "runtimeBytes": 400 << 20},
			}
			refused := 60
			test.edit(&s, &refused)
			c := &harness.Case{ID: "capacity.mixed-caps", Title: "classified capacity", Label: harness.Requires10, ReleaseBlocker: loadAttributionBlocker("capacity.mixed-caps")}
			c.Run = func(check *harness.T) {
				e := &Env{T: check, deferAttribution: true}
				credit := e.capacityAccounting("test", "tcp", engine.Stats{}, s, 150, 90, refused, false)
				e.exactCapacity("test", 90, 100, credit)
			}
			report := harness.Run(context.Background(), []*harness.Case{c}, harness.NewReport(), harness.Options{Kind: harness.V1, OutDir: t.TempDir(), Console: io.Discard})
			if report.JobFailed != test.fail {
				t.Fatalf("classification escaped hard checks: %+v", report)
			}
			if !test.fail && report.Cases[0].Outcome != harness.ReleaseBlocked {
				t.Fatalf("short occupancy was called a release pass: %+v", report)
			}
		})
	}
}
