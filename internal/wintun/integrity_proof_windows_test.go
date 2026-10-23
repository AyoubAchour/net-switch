//go:build windows

package wintun

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"
)

func integrityProofRatios(clean, observed []performanceSample) ([]float64, error) {
	if len(clean) == 0 || len(clean) != len(observed) {
		return nil, fmt.Errorf("diagnostic proof incomplete: missing pairs")
	}
	a, b := make([]float64, len(clean)), make([]float64, len(clean))
	for i := range clean {
		for _, s := range []performanceSample{clean[i], observed[i]} {
			if s.Status != "valid" || s.Value == nil || s.Pair != i || s.Error != "" {
				return nil, fmt.Errorf("diagnostic proof incomplete: pair=%d status=%s verdict=%s error=%s", i, s.Status, integrityVerdict(s.cause), s.Error)
			}
		}
		a[i], b[i] = *observed[i].Value, *clean[i].Value
	}
	return pairedRatios(a, b)
}

func integrityProofQualified(ratios []float64) bool {
	return len(ratios) != 0 && median(ratios) >= 0.80
}

type integrityModeOverhead struct {
	Pairs   int      `json:"pairs"`
	Median  *float64 `json:"median_diagnostic_over_clean"`
	Verdict string   `json:"verdict"`
}

func integrityModeResult(ratios []float64, expected int) integrityModeOverhead {
	r := integrityModeOverhead{Pairs: len(ratios), Verdict: "diagnostic_incomplete"}
	if len(ratios) != expected || expected == 0 {
		return r
	}
	m := median(ratios)
	r.Median, r.Verdict = &m, "valid"
	if !integrityProofQualified(ratios) {
		r.Verdict = "diagnostic_invalid"
	}
	return r
}

func integrityProofScope(scenario, boundary string) ([]string, []string, error) {
	boundaries := []string{"receive", "ingress", "echo", "output", "send", "host"}
	modes := []string{"ours", "dll"}
	switch scenario {
	case "", "proof":
		return boundaries, modes, nil
	case "isolated", "full":
		switch boundary {
		case "receive", "ingress", "echo", "output", "send", "host", "all":
		default:
			return nil, nil, fmt.Errorf("%v: unknown calibration boundary %q", errDiagnosticIncomplete, boundary)
		}
		if scenario == "full" {
			modes = append(modes, "inprocess")
		}
		return []string{boundary}, modes, nil
	default:
		return nil, nil, fmt.Errorf("%v: unknown calibration scenario %q", errDiagnosticIncomplete, scenario)
	}
}

// A qualification test, not corruption exposure. Compare the original clean
// workload to the actual instrumented workload, with no discarded samples or
// retries. Each mode's median across its paired ratios must retain >=80%.
func TestWintunIntegrityProof(t *testing.T) {
	requireRunner(t)
	if !integrityHooksEnabled {
		t.Fatal("proof requires -tags=wintun_integrity")
	}
	useProductionRegistrar(t, "integrity_proof_registrar")
	t.Setenv("NETSWITCH_WINTUN_INTEGRITY_TRACE", "0")
	// Exposure jobs calibrate after their original sequence, on the boundary
	// and implementations actually used by that job. No prelude state is reset.
	boundaries, modes, err := integrityProofScope(os.Getenv("NETSWITCH_WINTUN_INTEGRITY_SCENARIO"), os.Getenv("NETSWITCH_WINTUN_INTEGRITY_BOUNDARY"))
	must(t, err)
	completed := 0
	var allRatios []float64
	modeRatios := make(map[string][]float64)
	for _, boundary := range boundaries {
		for _, mode := range modes {
			t.Run(boundary+"/"+mode, func(t *testing.T) {
				const pairs = 3
				clean := newPerformanceSamples(pairs, "clean", boundary)
				observed := newPerformanceSamples(pairs, "diagnostic", boundary)
				for pair := range pairs {
					t.Run(fmt.Sprintf("pair%d", pair), func(t *testing.T) {
						a := newAdapter(t, 0)
						order := []bool{false, true}
						if pair%2 != 0 {
							order = []bool{true, false}
						}
						for _, diagnostic := range order {
							label, enabled, samples := "clean", "0", clean
							if diagnostic {
								label, enabled, samples = "diagnostic", "1", observed
							}
							t.Run(label, func(t *testing.T) {
								t.Setenv("NETSWITCH_WINTUN_INTEGRITY", enabled)
								t.Setenv("NETSWITCH_WINTUN_INTEGRITY_BOUNDARY", boundary)
								sample := &samples[pair]
								started := time.Now()
								var f *fixture
								t.Cleanup(func() {
									if t.Failed() && sample.cause == nil {
										err := errors.New("proof setup/teardown failed")
										if f != nil && f.integrity != nil {
											err = errors.Join(err, f.integrity.err())
										}
										sample.finish(0, err)
									}
									report(t, map[string]any{"test": "integrity_proof_sample", "boundary": boundary, "mode": mode, "sample": sample, "wall_seconds": time.Since(started).Seconds(), "verdict": integrityVerdict(sample.cause)})
									var memory runtime.MemStats
									runtime.ReadMemStats(&memory)
									report(t, map[string]any{"test": "integrity_proof_memory", "boundary": boundary, "mode": mode, "sample_mode": label, "heap_alloc": memory.HeapAlloc, "heap_sys": memory.HeapSys})
								})
								f = fixtureOnAdapter(t, mode, a)
								f.stopEcho()
								f.stopEcho = tcpEcho(t, f)
								for warm := range 2 {
									_, err := tcpTransfer(t, f, 1, fmt.Sprintf("warmup%d", warm))
									if err != nil {
										sample.finish(0, err)
										t.Fatal(err)
									}
								}
								value, err := tcpTransfer(t, f, 8, "measured")
								sample.finish(value, errors.Join(err, f.fault()))
								must(t, sample.cause)
							})
						}
					})
				}
				ratios, err := integrityProofRatios(clean, observed)
				if err != nil {
					t.Error(err)
					return
				}
				report(t, map[string]any{"test": "integrity_overhead", "verdict": "observed", "boundary": boundary, "mode": mode, "median_diagnostic_over_clean": median(ratios), "pair_ratios": ratios, "clean": clean, "diagnostic": observed, "minimum_ratio": 0.80, "arch": os.Getenv("RUNNER_ARCH")})
				allRatios = append(allRatios, ratios...)
				modeRatios[mode] = append(modeRatios[mode], ratios...)
				completed++
			})
		}
	}
	expected := len(boundaries) * len(modes)
	verdict := "valid"
	modeResults := make(map[string]integrityModeOverhead)
	for _, mode := range modes {
		r := integrityModeResult(modeRatios[mode], len(boundaries)*3)
		modeResults[mode] = r
		if r.Verdict == "diagnostic_invalid" {
			verdict = "diagnostic_invalid"
		}
	}
	if completed != expected {
		verdict = "diagnostic_incomplete"
		t.Errorf("%v: only %d/%d configurations measured", errDiagnosticIncomplete, completed, expected)
	}
	var overallMedian any
	if completed == expected {
		overallMedian = median(allRatios)
	}
	report(t, map[string]any{"test": "integrity_proof_complete", "verdict": verdict, "completed_configurations": completed,
		"expected_configurations": expected, "boundaries": boundaries, "modes": modes, "expected_pairs": expected * 3, "pair_ratios": allRatios,
		"median_diagnostic_over_clean": overallMedian, "qualification_scope": "per_mode", "mode_results": modeResults, "minimum_ratio": 0.80})
}

func TestIntegrityModesIndependent(t *testing.T) {
	for _, slow := range []string{"ours", "dll", "inprocess"} {
		for _, mode := range []string{"ours", "dll", "inprocess"} {
			ratios := []float64{1, 1, 1}
			want := "valid"
			if mode == slow {
				ratios, want = []float64{.7, .7, .7}, "diagnostic_invalid"
			}
			if got := integrityModeResult(ratios, 3); got.Verdict != want {
				t.Fatalf("%s masked %s: %+v", mode, slow, got)
			}
		}
	}
	if r := integrityModeResult([]float64{1, 1}, 3); r.Median != nil || r.Verdict != "diagnostic_incomplete" {
		t.Fatal(r)
	}
}

func TestIntegrityModeOverheadBound(t *testing.T) {
	// Actual failed ARM64 ingress/ours samples from job 120245044279.
	if integrityProofQualified([]float64{0.7877527415460567, 1.0051356856412232, 0.7857552788965874}) {
		t.Fatal("mode median below 0.80 accepted")
	}
	// One faster observation must not hide a consistently >20% slower path.
	for _, ratios := range [][]float64{{0.79, 0.79, 0.79}, {0.79, 1.2, 0.79}, nil} {
		if integrityProofQualified(ratios) {
			t.Fatal("overhead bound accepted", ratios)
		}
	}
	if !integrityProofQualified([]float64{0.8, 0.8, 0.8}) {
		t.Fatal("exact 20% boundary changed")
	}
	// Each mode pools its boundary pairs. A slow boundary remains visible in
	// the spread, but cannot be diluted by another implementation's speed.
	ratios := []float64{0.7877527415460567, 1.0051356856412232, 0.7857552788965874}
	for range 15 {
		ratios = append(ratios, 0.9)
	}
	if !integrityProofQualified(ratios) {
		t.Fatal("job still gated on one boundary")
	}
}

func TestIntegrityProofScope(t *testing.T) {
	for _, scenario := range []string{"proof", "isolated", "full"} {
		b, m, err := integrityProofScope(scenario, "ingress")
		want := 6
		if scenario == "proof" {
			want = 36
		}
		if scenario == "full" {
			want = 9
		}
		if err != nil || len(b)*len(m)*3 != want {
			t.Fatalf("%s: %v %v %v", scenario, b, m, err)
		}
		if scenario != "proof" && b[0] != "ingress" {
			t.Fatal("calibrated an unselected boundary")
		}
	}
	if _, _, err := integrityProofScope("full", ""); err == nil {
		t.Fatal("missing boundary accepted")
	}
	if _, _, err := integrityProofScope("unknown", "ingress"); err == nil {
		t.Fatal("unknown scope accepted")
	}
}

func TestIntegrityProofKeepsInvalidPairs(t *testing.T) {
	a, b := newPerformanceSamples(3, "clean", "receive"), newPerformanceSamples(3, "diagnostic", "receive")
	for i := range a {
		a[i].finish(800, nil)
		b[i].finish(680, nil)
	}
	r, err := integrityProofRatios(a, b)
	if err != nil || median(r) != 0.85 {
		t.Fatalf("%v %v", r, err)
	}
	b[1].finish(0, errDiagnosticIncomplete)
	if r, err := integrityProofRatios(a, b); err == nil || r != nil {
		t.Fatal("incomplete identity accepted as a valid speed measurement")
	}
	if integrityVerdict(b[1].cause) != "diagnostic_incomplete" {
		t.Fatal("incomplete identity counted as corruption")
	}
}
