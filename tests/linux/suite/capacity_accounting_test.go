//go:build linux

package suite

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/tests/linux/app"
	"github.com/AyoubAchour/net-switch/tests/linux/engine"
	"github.com/AyoubAchour/net-switch/tests/linux/harness"
)

func runCapacityCheck(t *testing.T, run func(*Env)) *harness.Report {
	t.Helper()
	c := &harness.Case{ID: "capacity.mixed-caps", Title: "capacity evidence", Label: harness.Requires10, ReleaseBlocker: loadAttributionBlocker("capacity.mixed-caps")}
	c.Run = func(check *harness.T) { run(&Env{T: check, deferAttribution: true}) }
	return harness.Run(context.Background(), []*harness.Case{c}, harness.NewReport(), harness.Options{Kind: harness.V1, OutDir: t.TempDir(), Console: io.Discard})
}
// runHardCheck runs checks in a case with no declared release blocker, so a
// fixture that makes no release assertion is not an incomplete declaration.
func runHardCheck(t *testing.T, run func(*Env)) *harness.Report {
	t.Helper()
	c := &harness.Case{ID: "capacity.hard-checks", Title: "hard checks", Label: harness.Requires10}
	c.Run = func(check *harness.T) { run(&Env{T: check}) }
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
			outboundFailure := "no outbound TCP dial failed"
			if protocol == "udp" {
				outboundFailure = "no native UDP open failed"
			}
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
				{"outbound failure", outboundFailure, func(s *engine.Stats, _ *flows.Refusals, _ *int) {
					if protocol == "udp" {
						s.Counters["udpOpenFailed"] = 1
					} else {
						s.Counters["tcpDialFailed"] = 1
					}
				}},
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
				{"no observed unknown cap", "matching engine peak", func(s *engine.Stats, _ *flows.Refusals, _ *int) { s.PeakUnknown = 0; s.PeakUnknownUDP = 0 }},
				{"heap exceeded", "forced-GC live heap", func(s *engine.Stats, _ *flows.Refusals, _ *int) { s.Counters["forcedGCHeapBytes"] = liveHeapLimit + 1 }},
				{"heap missing", "forced-GC live heap", func(s *engine.Stats, _ *flows.Refusals, _ *int) { delete(s.Counters, "forcedGCHeapBytes") }},
				{"managed above old limit", "", func(s *engine.Stats, _ *flows.Refusals, _ *int) { s.Counters["runtimeBytes"] = 600 << 20 }},
				{"pool exceeded", "never exceed their caps", func(s *engine.Stats, _ *flows.Refusals, _ *int) { s.PeakUnknown = 2049 }},
				{"per-app cap exceeded", "never exceed their caps", func(s *engine.Stats, _ *flows.Refusals, _ *int) { s.PeakPerApp = 8193 }},
				{"total cap exceeded", "never exceed their caps", func(s *engine.Stats, _ *flows.Refusals, _ *int) { s.PeakFlows = 65537 }},
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
						credit := e.capacityAccounting("test", protocol, engine.Stats{}, s, heldBase{}, 150, 90, refused, scope)
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
			e.capacityAccounting("udp", "udp", engine.Stats{}, s, heldBase{}, 150, 90, 60, capacityTotal)
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

// mixedApp builds one app's server-side view: TCP connections whose probes
// the servers saw from each source address, and UDP sockets per line.
func mixedApp(tcp map[string]int, udp map[engine.LineID]int) (app.HeldList, sessions) {
	var list app.HeldList
	for _, src := range []string{"203.0.113.2", "192.0.2.1", "192.0.2.5", ""} {
		for range tcp[src] {
			c := app.Held{Local: fmt.Sprintf("10.0.%d.%d:%d", len(list.Conns)/250, len(list.Conns)%250, 40000+len(list.Conns)%20000), Remote: "198.51.100.10:7"}
			if src != "" {
				c.Seen = fmt.Sprintf("%s:%d", src, 30000+len(list.Conns))
			}
			list.Conns = append(list.Conns, c)
		}
	}
	list.Established = len(list.Conns)
	return list, sessions{serverLines: udp}
}

func TestMixedCapacityCountsOnlyServerObservedIdentifiedSockets(t *testing.T) {
	const c, a, b = "203.0.113.2", "192.0.2.1", "192.0.2.5"
	for _, test := range []struct {
		name string
		tcp  map[string]int
		udp  map[engine.LineID]int
		line engine.LineID
		dupe bool
		full bool
		on   [2]int
	}{
		{"full with an unknown TCP extra", map[string]int{c: 4192, a: 1}, map[engine.LineID]int{"c": 4000}, "c", false, true, [2]int{4192, 4000}},
		{"full with an unknown UDP extra", map[string]int{c: 4192}, map[engine.LineID]int{"c": 4000, "a": 1}, "c", false, true, [2]int{4192, 4000}},
		{"full with unknown extras on both", map[string]int{c: 4192, a: 3}, map[engine.LineID]int{"c": 4000, "a": 2}, "c", false, true, [2]int{4192, 4000}},
		{"one short, an unknown TCP makes 8192", map[string]int{c: 4191, a: 1}, map[engine.LineID]int{"c": 4000}, "c", false, false, [2]int{4191, 4000}},
		{"one short, an unknown UDP makes 8192", map[string]int{c: 4192}, map[engine.LineID]int{"c": 3999, "a": 1}, "c", false, false, [2]int{4192, 3999}},
		{"TCP-only app", map[string]int{c: 8192}, nil, "c", false, false, [2]int{8192, 0}},
		{"TCP-only app with unknown UDP", map[string]int{c: 8192}, map[engine.LineID]int{"a": 1}, "c", false, false, [2]int{8192, 0}},
		{"TCP left on the wrong line", map[string]int{c: 4191, b: 1}, map[engine.LineID]int{"c": 4000}, "c", false, false, [2]int{4191, 4000}},
		{"UDP left on the wrong line", map[string]int{c: 4192}, map[engine.LineID]int{"c": 3999, "b": 1}, "c", false, false, [2]int{4192, 3999}},
		{"TCP without a server observation", map[string]int{c: 4191, "": 1}, map[engine.LineID]int{"c": 4000}, "c", false, false, [2]int{4191, 4000}},
		{"over the cap", map[string]int{c: 4193}, map[engine.LineID]int{"c": 4000}, "c", false, false, [2]int{4193, 4000}},
		{"repeated tuple counts once", map[string]int{c: 4191}, map[engine.LineID]int{"c": 4000}, "c", true, false, [2]int{4191, 4000}},
		{"pin to main cannot separate unknowns", map[string]int{a: 4192}, map[engine.LineID]int{"a": 4000}, "a", false, false, [2]int{0, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			list, udp := mixedApp(test.tcp, test.udp)
			if test.dupe {
				list.Conns = append(list.Conns, list.Conns[0])
				list.Established++
			}
			full, tcpOn, udpOn := fullIdentifiedApp(list, udp, test.line)
			if full != test.full || [2]int{tcpOn, udpOn} != test.on {
				t.Fatalf("got full=%t TCP=%d UDP=%d, want full=%t %v", full, tcpOn, udpOn, test.full, test.on)
			}
			// The verdict is the only thing that lets a mixed per-app refusal pass.
			s := engine.Stats{Flows: 90, Admitted: 90, LookupMisses: 10, RefusedTCP: flows.Refusals{PerApp: 50, Unknown: 10}, PeakPerApp: 8192, PeakUnknown: 2048, Counters: map[string]uint64{"tcpRejected": 60, "forcedGCHeapBytes": 400 << 20}}
			report := runCapacityCheck(t, func(e *Env) {
				credit := e.capacityAccounting("mixed", "tcp", engine.Stats{}, s, heldBase{}, 150, 90, 60, capacityMixed, full)
				e.exactCapacity("mixed", 90, 100, credit)
			})
			if !test.full {
				requireFailure(t, report, "UDP-holding client app")
			} else if report.JobFailed {
				t.Fatal(report)
			}
		})
	}
}

func TestTCPRepeatedCapDecisionsCannotHideShortfall(t *testing.T) {
	s := engine.Stats{Flows: 90, Admitted: 90, LookupMisses: 10, RefusedTCP: flows.Refusals{Total: 70, Unknown: 10}, PeakFlows: 65536, PeakUnknown: 2048, Counters: map[string]uint64{"tcpRejected": 80, "forcedGCHeapBytes": 400 << 20}}
	report := runCapacityCheck(t, func(e *Env) {
		credit := e.capacityAccounting("tcp", "tcp", engine.Stats{}, s, heldBase{}, 150, 90, 60, capacityTotal)
		e.exactCapacity("tcp", 90, 100, credit)
	})
	requireFailure(t, report, "whole exact-cap shortfall")
}

// The review's false pass: one real stream, a leaked engine count of 2 at the
// first sample, then 8,192 held and an engine count of 8,194. The delta is
// right, so only absolute equality with the independent holders catches the
// phantom. Every scope and transport carries the same offset through both
// samples; the honest counts pass.
func TestCapacityPhantomOffsetThroughBothSamplesFails(t *testing.T) {
	const held = 8192
	// Every capacityAccounting call shape in the suite, with its real baseline.
	for _, shape := range []struct {
		name     string
		protocol string
		scope    capacityScope
		base     heldBase
	}{
		{"UDP per-app", "udp", capacityPerApp, streamBase},
		{"UDP total", "udp", capacityTotal, streamBase},
		{"TCP per-app", "tcp", capacityPerApp, streamBase},
		{"TCP total", "tcp", capacityTotal, streamBase},
		{"TCP total tail", "tcp", capacityTotal, heldBase{tcp: 58642 + 1}},
		{"mixed UDP", "udp", capacityTotal, heldBase{}},
		{"mixed TCP", "tcp", capacityMixed, heldBase{udp: 16384}},
		{"mixed tail", "tcp", capacityTotal, heldBase{tcp: 49148, udp: 16384}},
	} {
		for _, phantom := range []struct {
			name       string
			flows, udp int64
		}{
			{"honest", 0, 0},
			{"phantom TCP flow in both samples", 2, 0},
			{"phantom UDP session in both samples", 1, 1},
		} {
			t.Run(shape.name+"/"+phantom.name, func(t *testing.T) {
				baseFlows, baseUDP := int64(shape.base.tcp+shape.base.udp), int64(shape.base.udp)
				before := engine.Stats{Flows: baseFlows + phantom.flows, UDP: baseUDP + phantom.udp, Counters: map[string]uint64{}}
				after := engine.Stats{Flows: before.Flows + held, UDP: before.UDP, Admitted: held, PeakFlows: tcpFlowsTotal, PeakUDP: udpSessionsTotal, PeakPerApp: tcpFlowsPerApp, PeakUDPPerApp: udpSessionsPerApp,
					Counters: map[string]uint64{"forcedGCHeapBytes": 400 << 20}}
				if shape.protocol == "udp" {
					after.UDP += held
				}
				report := runHardCheck(t, func(e *Env) {
					e.capacityAccounting("phantom", shape.protocol, before, after, shape.base, held, held, 0, shape.scope, true)
				})
				for _, check := range report.Cases[0].Checks {
					if strings.Contains(check.Message, "delta equals") && !check.OK {
						t.Fatalf("the offset must keep the delta right, so only absolute equality can catch it: %+v", check)
					}
				}
				if phantom.flows == 0 {
					if report.JobFailed {
						t.Fatalf("honest counts failed: %+v", report.Cases[0])
					}
					return
				}
				requireFailure(t, report, "engine baseline equals independently observed holders")
				requireFailure(t, report, "engine absolute count equals independently held clients plus baseline holders")
			})
		}
	}
}
