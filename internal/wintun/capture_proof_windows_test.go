//go:build windows

package wintun

import (
	"errors"
	"fmt"
	"runtime"
	"testing"
)

// Same executable, payload, hash, warmups and socket read sizes. Only the
// bytes.Equal reader is disabled in the baseline. No failed pair is replaced.
func TestWintunCaptureProof(t *testing.T) {
	requireRunner(t)
	useProductionRegistrar(t, "capture_proof_registrar")
	t.Setenv("NETSWITCH_WINTUN_INTEGRITY", "0")
	t.Setenv("NETSWITCH_WINTUN_INTEGRITY_TRACE", "0")
	for _, mode := range []string{"ours", "dll"} {
		t.Run(mode, func(t *testing.T) {
			const pairs = 8
			clean, observed := newPerformanceSamples(pairs, "sha_only", "tcp_8_MBps"), newPerformanceSamples(pairs, "capture", "tcp_8_MBps")
			for pair := range pairs {
				t.Run(fmt.Sprintf("pair%d", pair), func(t *testing.T) {
					a := newAdapter(t, 0)
					order := []bool{false, true}
					if pair%2 != 0 {
						order = []bool{true, false}
					}
					for _, capture := range order {
						label, samples := "sha_only", clean
						if capture {
							label, samples = "capture", observed
						}
						t.Run(label, func(t *testing.T) {
							sample := &samples[pair]
							t.Cleanup(func() {
								if t.Failed() && sample.cause == nil {
									sample.finish(0, errors.New("capture proof setup/teardown failed"))
								}
								report(t, map[string]any{"test": "capture_proof_sample", "mode": mode, "sample": sample})
							})
							f := fixtureOnAdapter(t, mode, a)
							f.skipPayloadCapture = !capture
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
				t.Fatal(err)
			}
			ratio := median(ratios)
			report(t, map[string]any{"test": "capture_overhead", "arch": runtime.GOARCH, "mode": mode, "pairs": pairs, "clean": clean, "capture": observed, "pair_ratios": ratios, "median_capture_over_clean": ratio, "minimum_ratio": 0.95})
			if ratio < 0.95 {
				t.Errorf("capture throughput ratio %.4f < 0.95; overhead needs investigation", ratio)
			}
		})
	}
}
