//go:build linux

package suite

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/tests/linux/engine"
	"github.com/AyoubAchour/net-switch/tests/linux/harness"
)

func runCapacityCheck(t *testing.T, run func(*Env)) *harness.Report {
	t.Helper()
	c := &harness.Case{ID: "capacity.mixed-caps", Title: "capacity evidence", Label: harness.Requires10, ReleaseBlocker: loadAttributionBlocker("capacity.mixed-caps")}
	c.Run = func(check *harness.T) { run(&Env{T: check, deferAttribution: true}) }
	return harness.Run(context.Background(), []*harness.Case{c}, harness.NewReport(), harness.Options{Kind: harness.V1, OutDir: t.TempDir(), Console: io.Discard})
}
func requireFailure(t *testing.T, report *harness.Report, message string) {
	t.Helper()
	if !report.JobFailed {
		t.Fatalf("missing hard failure %q: %+v", message, report)
	}
	for _, check := range report.Cases[0].Checks {
		if !check.OK && !check.ReleaseBlocker && strings.Contains(check.Message, message) {
			return
		}
	}
	t.Fatalf("failed for the wrong reason, wanted %q: %+v", message, report.Cases[0])
}

func TestCapacityShortfallNeedsCompleteRefusalEvidence(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		for _, scope := range []capacityScope{capacityTotal, capacityPerApp} {
			for _, test := range []struct {
				name, failure string
				edit          func(*engine.Stats, *flows.Refusals, *int)
			}{
				{"proved unknown overflow", "", func(*engine.Stats, *flows.Refusals, *int) {}},
				{"wrong transport cap", "every refusal decision", func(_ *engine.Stats, r *flows.Refusals, _ *int) {
					if protocol == "tcp" {
						r.UDP++
					} else {
						r.Total++
					}
				}},
				{"wrong scope cap", "every refusal decision", func(_ *engine.Stats, r *flows.Refusals, _ *int) {
					if scope == capacityTotal {
						r.PerApp++
					} else {
						r.Total++
					}
				}},
				{"policy refusal", "every refusal decision", func(_ *engine.Stats, r *flows.Refusals, _ *int) { r.Policy++ }},
				{"handshake refusal", "every refusal decision", func(_ *engine.Stats, r *flows.Refusals, _ *int) { r.Handshakes++ }},
				{"unexplained refusal", "every refusal decision", func(_ *engine.Stats, r *flows.Refusals, _ *int) { r.Unexplained++ }},
				{"lost admitted flow", "every admitted flow", func(s *engine.Stats, _ *flows.Refusals, _ *int) { s.Admitted++ }},
				{"phantom flow", "engine flow delta", func(s *engine.Stats, _ *flows.Refusals, _ *int) { s.Flows++ }},
				{"lost client attempt", "every offered attempt", func(_ *engine.Stats, _ *flows.Refusals, r *int) { *r-- }},
				{"missing forwarding decision", "every refusal decision", func(s *engine.Stats, _ *flows.Refusals, _ *int) { s.Counters[protocol+"Rejected"]++ }},
				{"no observed cap", "matching engine peak", func(s *engine.Stats, _ *flows.Refusals, _ *int) {
					s.PeakFlows = 0
					s.PeakUDP = 0
					s.PeakPerApp = 0
					s.PeakUDPPerApp = 0
				}},
				{"unclassified miss", "every missed lookup", func(s *engine.Stats, _ *flows.Refusals, _ *int) { s.LookupMisses++ }},
				{"heap exceeded", "forced-GC live heap", func(s *engine.Stats, _ *flows.Refusals, _ *int) { s.Counters["forcedGCHeapBytes"] = liveHeapLimit + 1 }},
				{"heap missing", "forced-GC live heap", func(s *engine.Stats, _ *flows.Refusals, _ *int) { delete(s.Counters, "forcedGCHeapBytes") }},
				{"managed above old limit", "", func(s *engine.Stats, _ *flows.Refusals, _ *int) { s.Counters["runtimeBytes"] = 600 << 20 }},
				{"pool exceeded", "never exceed their caps", func(s *engine.Stats, _ *flows.Refusals, _ *int) { s.PeakUnknown = 2049 }},
			} {
				t.Run(protocol+"/"+string(rune('0'+scope))+"/"+test.name, func(t *testing.T) {
					s := engine.Stats{Flows: 90, Admitted: 90, LookupMisses: 10, PeakFlows: tcpFlowsTotal, PeakUDP: udpSessionsTotal, PeakPerApp: tcpFlowsPerApp, PeakUDPPerApp: udpSessionsPerApp, PeakUnknown: 2048, PeakUnknownUDP: 512, Counters: map[string]uint64{protocol + "Rejected": 60, "forcedGCHeapBytes": 400 << 20, "runtimeBytes": 400 << 20}}
					r := flows.Refusals{Unknown: 10}
					if protocol == "udp" {
						s.UDP = 90
						r = flows.Refusals{UnknownUDP: 10}
						if scope == capacityTotal {
							r.UDP = 50
						} else {
							r.UDPPerApp = 50
						}
					} else if scope == capacityTotal {
						r.Total = 50
					} else {
						r.PerApp = 50
					}
					refused := 60
					test.edit(&s, &r, &refused)
					if protocol == "udp" {
						s.RefusedUDP = r
					} else {
						s.RefusedTCP = r
					}
					report := runCapacityCheck(t, func(e *Env) {
						credit := e.capacityAccounting("test", protocol, engine.Stats{}, s, 150, 90, refused, scope)
						e.exactCapacity("test", 90, 100, credit)
					})
					if test.failure != "" {
						requireFailure(t, report, test.failure)
					} else if report.JobFailed || report.Cases[0].Outcome != harness.ReleaseBlocked {
						t.Fatalf("valid attribution evidence: %+v", report)
					}
				})
			}
		}
	}
}

func TestUDPAccountingRequiresExactDecisionCountAndRealSessions(t *testing.T) {
	for _, variant := range []string{"exact", "extra decision", "phantom UDP"} {
		s := engine.Stats{Flows: 90, UDP: 90, Admitted: 90, PeakUDP: udpSessionsTotal, RefusedUDP: flows.Refusals{UDP: 60}, Counters: map[string]uint64{"udpRejected": 60, "forcedGCHeapBytes": 400 << 20}}
		if variant == "extra decision" {
			s.RefusedUDP.UDP++
			s.Counters["udpRejected"]++
		}
		if variant == "phantom UDP" {
			s.UDP++
		}
		report := runCapacityCheck(t, func(e *Env) {
			e.capacityAccounting("udp", "udp", engine.Stats{}, s, 150, 90, 60, capacityTotal)
			e.exactCapacity("udp", 90, 90, 0)
		})
		switch variant {
		case "exact":
			if report.JobFailed {
				t.Fatal(report)
			}
		case "extra decision":
			requireFailure(t, report, "every refusal decision")
		case "phantom UDP":
			requireFailure(t, report, "engine UDP delta")
		}
	}
}

func TestMixedCapacityAcceptsOnlyAnActuallyFullCombinedAppPool(t *testing.T) {
	for _, independent := range []bool{false, true} {
		s := engine.Stats{Flows: 90, Admitted: 90, LookupMisses: 10, RefusedTCP: flows.Refusals{PerApp: 50, Unknown: 10}, PeakPerApp: 8192, PeakUnknown: 2048, Counters: map[string]uint64{"tcpRejected": 60, "forcedGCHeapBytes": 400 << 20}}
		report := runCapacityCheck(t, func(e *Env) {
			e.capacityAccounting("mixed", "tcp", engine.Stats{}, s, 150, 90, 60, capacityMixed, independent)
		})
		if !independent {
			requireFailure(t, report, "UDP-holding client app")
		} else if report.JobFailed {
			t.Fatal(report)
		}
	}
}

func TestTCPRepeatedCapDecisionsCannotHideShortfall(t *testing.T) {
	s := engine.Stats{Flows: 90, Admitted: 90, LookupMisses: 10, RefusedTCP: flows.Refusals{Total: 70, Unknown: 10}, PeakFlows: 65536, PeakUnknown: 2048, Counters: map[string]uint64{"tcpRejected": 80, "forcedGCHeapBytes": 400 << 20}}
	report := runCapacityCheck(t, func(e *Env) {
		credit := e.capacityAccounting("tcp", "tcp", engine.Stats{}, s, 150, 90, 60, capacityTotal)
		e.exactCapacity("tcp", 90, 100, credit)
	})
	requireFailure(t, report, "whole exact-cap shortfall")
}
