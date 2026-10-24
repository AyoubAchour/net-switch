//go:build windows

package wintun

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Each sample has the same process/adapter lifetime, payload preparation,
// warmups and traffic. The baseline binary has no boundary hooks compiled in.
func TestWintunBoundarySample(t *testing.T) {
	mode := os.Getenv("NETSWITCH_BOUNDARY_SAMPLE")
	if mode == "" {
		t.Skip("sample subprocess only")
	}
	requireRunner(t)
	useProductionRegistrar(t, "boundary_sample_registrar")
	t.Setenv("NETSWITCH_WINTUN_INTEGRITY", "0")
	f := newFixture(t, mode, 0)
	f.stopEcho()
	f.stopEcho = tcpEcho(t, f)
	for i := 0; i < 2; i++ {
		_, err := tcpTransfer(t, f, 1, fmt.Sprintf("warmup%d", i))
		must(t, err)
	}
	f.captureVariant = "baseline"
	if os.Getenv("NETSWITCH_WINTUN_BOUNDARIES") == "1" {
		f.captureVariant = "diagnostic"
	}
	f.capturePair, _ = strconv.Atoi(os.Getenv("NETSWITCH_BOUNDARY_PAIR"))
	rate, err := tcpTransfer(t, f, 8, "measured")
	err = errors.Join(err, f.fault(), wordBoundaryRingFault(f))
	report(t, map[string]any{"test": "boundary_sample", "mode": mode, "variant": f.captureVariant, "pair": f.capturePair, "MBps": rate, "verdict": integrityVerdict(err)})
	must(t, err)
}

type boundaryProofSample struct {
	Mode    string  `json:"mode"`
	Variant string  `json:"variant"`
	Pair    int     `json:"pair"`
	MBps    float64 `json:"MBps"`
	CPU     float64 `json:"cpu_ms"`
	Peak    uint64  `json:"peak_working_set_bytes"`
}

func TestWintunBoundaryProof(t *testing.T) {
	requireRunner(t)
	baseline, err := filepath.Abs(os.Getenv("NETSWITCH_BOUNDARY_BASELINE"))
	must(t, err)
	diagnostic, err := filepath.Abs(os.Getenv("NETSWITCH_BOUNDARY_DIAGNOSTIC"))
	must(t, err)
	if baseline == diagnostic || os.Getenv("NETSWITCH_BOUNDARY_BASELINE") == "" || os.Getenv("NETSWITCH_BOUNDARY_DIAGNOSTIC") == "" {
		t.Fatal("distinct baseline and tagged executables required")
	}
	for _, mode := range []string{"ours", "dll"} {
		t.Run(mode, func(t *testing.T) {
			var samples []boundaryProofSample
			var ratios, cpuRatios []float64
			for pair := 0; pair < 8; pair++ {
				order := []bool{false, true}
				if pair%2 != 0 {
					order = []bool{true, false}
				}
				var result [2]boundaryProofSample
				for _, enabled := range order {
					exe, variant, index := baseline, "baseline", 0
					if enabled {
						exe, variant, index = diagnostic, "diagnostic", 1
					}
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
					cmd := exec.CommandContext(ctx, exe, "-test.v", "-test.run=^TestWintunBoundarySample$", "-test.timeout=90s")
					flag := "0"
					if enabled {
						flag = "1"
					}
					cmd.Env = append(os.Environ(), "NETSWITCH_WINTUN_BOUNDARIES="+flag, "NETSWITCH_BOUNDARY_SAMPLE="+mode, "NETSWITCH_BOUNDARY_PAIR="+strconv.Itoa(pair))
					output, runErr := cmd.CombinedOutput()
					cancel()
					// Print the child records, including bounded mismatch evidence,
					// without discarding slow or failed samples.
					scanner := bufio.NewScanner(bytes.NewReader(output))
					scanner.Buffer(make([]byte, 4096), 2<<20)
					var got boundaryProofSample
					found, resources, coverage := 0, 0, 0
					for scanner.Scan() {
						line := scanner.Text()
						t.Log(line) // Preserve raw recovery warnings and child failures too.
						pos := strings.Index(line, "WINTUN_RESULT ")
						if pos < 0 {
							continue
						}
						line = line[pos:]
						var r struct {
							Test, Mode, Variant, Verdict string
							Pair                         int
							MBps                         float64
							CPU                          float64 `json:"cpu_ms"`
							After                        captureResourceSnapshot
							Flows                        int
							ExpectedFlows                int `json:"expected_flows"`
						}
						must(t, json.Unmarshal([]byte(line[len("WINTUN_RESULT "):]), &r))
						switch r.Test {
						case "boundary_sample":
							found++
							if r.Mode != mode || r.Variant != variant || r.Pair != pair || r.Verdict != "ok" || r.MBps <= 0 {
								t.Fatalf("invalid sample: %s", line)
							}
							got.Mode, got.Variant, got.Pair, got.MBps = r.Mode, r.Variant, r.Pair, r.MBps
						case "capture_resources":
							resources++
							got.CPU, got.Peak = r.CPU, r.After.PeakWorkingSet
						case "word_boundary_coverage":
							if r.Verdict != "ok" || r.Flows != r.ExpectedFlows {
								t.Fatalf("incomplete boundary coverage: %s", line)
							}
							coverage += r.Flows
						}
					}
					must(t, scanner.Err())
					if runErr != nil {
						t.Fatalf("sample failed, no replacement: %v\n%s", runErr, output)
					}
					if found != 1 || resources != 1 || got.CPU <= 0 || got.Peak == 0 || enabled && coverage != 10 || !enabled && coverage != 0 {
						t.Fatalf("missing/duplicate evidence: samples=%d resources=%d coverage=%d", found, resources, coverage)
					}
					result[index] = got
					samples = append(samples, got)
				}
				ratios = append(ratios, result[1].MBps/result[0].MBps)
				cpuRatios = append(cpuRatios, result[1].CPU/result[0].CPU)
			}
			ratio := median(ratios)
			report(t, map[string]any{"test": "boundary_overhead", "arch": runtime.GOARCH, "mode": mode, "samples": samples, "pair_ratios": ratios, "cpu_pair_ratios": cpuRatios, "median_diagnostic_over_baseline": ratio, "median_cpu_ratio": median(cpuRatios), "minimum_ratio": 0.8, "baseline": "untagged_word_payload", "diagnostic": "all_four_boundaries"})
			if ratio < 0.8 {
				t.Errorf("boundary throughput ratio %.4f < 0.80: diagnostic overhead exceeds 20%%", ratio)
			}
		})
	}
}
