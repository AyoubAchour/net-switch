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

// A qualification test, not corruption exposure. Compare the original clean
// workload to the actual instrumented workload, with no discarded samples or
// retries. Each boundary and implementation must retain >=80% of throughput.
func TestWintunIntegrityProof(t *testing.T) {
	requireRunner(t)
	if !integrityHooksEnabled {
		t.Fatal("proof requires -tags=wintun_integrity")
	}
	useProductionRegistrar(t, "integrity_proof_registrar")
	t.Setenv("NETSWITCH_WINTUN_INTEGRITY_TRACE", "0")
	qualified := 0
	for _, boundary := range []string{"receive", "ingress", "echo", "output", "send", "host"} {
		for _, mode := range []string{"ours", "dll"} {
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
				ratio := median(ratios)
				verdict := "qualified"
				if ratio < 0.80 {
					verdict = "diagnostic_overhead_exceeded"
				}
				report(t, map[string]any{"test": "integrity_overhead", "verdict": verdict, "boundary": boundary, "mode": mode, "median_diagnostic_over_clean": ratio, "pair_ratios": ratios, "clean": clean, "diagnostic": observed, "minimum_ratio": 0.80, "arch": os.Getenv("RUNNER_ARCH")})
				if ratio < 0.80 {
					t.Errorf("diagnostic overhead too high: %s/%s throughput ratio %.3f < 0.80", boundary, mode, ratio)
				} else {
					qualified++
				}
			})
		}
	}
	report(t, map[string]any{"test": "integrity_proof_complete", "qualified_configurations": qualified, "expected_configurations": 12})
	if qualified != 12 {
		t.Errorf("only %d of 12 diagnostic configurations qualified", qualified)
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
