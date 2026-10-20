//go:build windows

package wintun

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestWintunLatencyClient(t *testing.T) {
	mode := os.Getenv("NETSWITCH_WINTUN_LATENCY_CLIENT")
	if mode != "ours" && mode != "dll" {
		t.Skip("latency client only")
	}
	requireRunner(t)
	fmt.Printf("LATENCY_RESULT %.9f\n", observedShortLatency(t, mode))
}

func latencyClient(t *testing.T, mode string) float64 {
	t.Helper()
	exe, err := os.Executable()
	must(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, exe, "-test.run=^TestWintunLatencyClient$", "-test.v")
	child.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	child.Env = append(os.Environ(), "NETSWITCH_WINTUN_LATENCY_CLIENT="+mode)
	output, err := child.CombinedOutput()
	if err != nil {
		t.Fatalf("latency child: %v\n%s", err, output)
	}
	t.Logf("child:\n%s", output)
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "LATENCY_RESULT ") {
			var latency float64
			_, err := fmt.Sscanf(line, "LATENCY_RESULT %f", &latency)
			must(t, err)
			return latency
		}
	}
	t.Fatal("latency child did not measure")
	return 0
}

func TestWintunLatencyProbe(t *testing.T) {
	requireRunner(t)
	report(t, map[string]any{"test": "latency_probe_host", "cpus": runtime.NumCPU(), "gomaxprocs": runtime.GOMAXPROCS(0), "monitor": os.Getenv("NETSWITCH_WINTUN_LATENCY_DIAGNOSTICS")})
	results := map[string]map[string][]float64{"same_process": {"dll": {}, "ours": {}}, "child_process": {"dll": {}, "ours": {}}}
	for trial := 0; trial < 6; trial++ {
		modes := []string{"dll", "ours"}
		placements := []string{"same_process", "child_process"}
		if trial%2 != 0 {
			modes[0], modes[1] = modes[1], modes[0]
			placements[0], placements[1] = placements[1], placements[0]
		}
		for _, mode := range modes {
			t.Run(fmt.Sprintf("trial%d/%s", trial, mode), func(t *testing.T) {
				f := newFixture(t, mode, 0)
				for _, placement := range placements {
					var before Stats
					s, _ := f.io.(*Session)
					if s != nil {
						before = s.Stats()
					}
					var latency float64
					if placement == "same_process" {
						latency = observedShortLatency(t, mode)
					} else {
						latency = latencyClient(t, mode)
					}
					results[placement][mode] = append(results[placement][mode], latency)
					fields := map[string]any{"test": "latency_probe", "trial": trial, "mode": mode, "placement": placement, "p95_us": latency, "before": before}
					if s != nil {
						fields["after"] = s.Stats()
					}
					report(t, fields)
					if err := f.fault(); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
	for placement, modes := range results {
		dll, own := median(modes["dll"]), median(modes["ours"])
		report(t, map[string]any{"test": "latency_probe_pooled", "placement": placement, "dll": dll, "ours": own, "ratio": own / dll, "samples": modes})
		if own > dll*1.10 {
			t.Errorf("%s latency regression: ours %.2f, DLL %.2f us", placement, own, dll)
		}
	}
}
