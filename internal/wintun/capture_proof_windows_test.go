//go:build windows

package wintun

import (
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Alternate the previous shared-payload/SHA-only workload with the complete
// word verifier and EOF workload. Both use one immutable 64 MiB Write and
// 32 KiB read requests. Preparation precedes timing AND resource counters.
// Never replace a failed pair or discard a slow pair.
func TestWintunCaptureProof(t *testing.T) {
	requireRunner(t)
	useProductionRegistrar(t, "capture_proof_registrar")
	t.Setenv("NETSWITCH_WINTUN_INTEGRITY", "0")
	t.Setenv("NETSWITCH_WINTUN_INTEGRITY_TRACE", "0")
	_, release := performancePayloads.prepare(0, 0, wordPayloadSize)
	release() // Same resident bank for every baseline and capture sample.
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
							f.captureVariant, f.capturePair = label, pair
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
			report(t, map[string]any{"test": "capture_overhead", "arch": runtime.GOARCH, "mode": mode, "pairs": pairs, "clean": clean, "capture": observed, "pair_ratios": ratios, "median_capture_over_clean": ratio, "minimum_ratio": 0.95, "resources": captureResources(t), "memory_scope": "process_lifetime_peak", "write_request_bytes": wordPayloadSize, "read_request_bytes": 32768, "payload_bank_bytes": 8 * wordPayloadSize})
			if ratio < 0.95 {
				t.Errorf("capture throughput ratio %.4f < 0.95; overhead needs investigation", ratio)
			}
		})
	}
}

type captureResourceSnapshot struct {
	CPUMillis      float64 `json:"cpu_ms"`
	Private        uint64  `json:"private_bytes"`
	Heap           uint64  `json:"heap_alloc_bytes"`
	HeapSys        uint64  `json:"heap_reserved_bytes"`
	Allocated      uint64  `json:"total_allocated_bytes"`
	WorkingSet     uint64  `json:"working_set_bytes"`
	PeakWorkingSet uint64  `json:"peak_working_set_bytes"`
}

func startCaptureResources(t *testing.T, f *fixture) func() {
	if f.captureVariant == "" {
		return func() {}
	}
	before := captureResources(t)
	started := time.Now()
	return func() {
		seconds := time.Since(started).Seconds()
		after := captureResources(t)
		report(t, map[string]any{"test": "capture_resources", "mode": f.mode, "pair": f.capturePair, "variant": f.captureVariant, "wall_seconds": seconds, "cpu_ms": after.CPUMillis - before.CPUMillis, "allocated_bytes": after.Allocated - before.Allocated, "before": before, "after": after})
	}
}

func captureResources(t *testing.T) captureResourceSnapshot {
	t.Helper()
	var created, exited, kernel, user windows.Filetime
	must(t, windows.GetProcessTimes(windows.CurrentProcess(), &created, &exited, &kernel, &user))
	_, private, ok := registrarUsage()
	if !ok {
		t.Fatal("process memory measurement failed")
	}
	type counters struct {
		Size, PageFaults                                                                                                          uint32
		PeakWorkingSet, WorkingSet, QuotaPeakPaged, QuotaPaged, QuotaPeakNonPaged, QuotaNonPaged, Pagefile, PeakPagefile, Private uintptr
	}
	mem := counters{}
	mem.Size = uint32(unsafe.Sizeof(mem))
	if ok, _, err := getProcessMemoryInfo.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&mem)), uintptr(mem.Size)); ok == 0 {
		t.Fatalf("process peak memory: %v", err)
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return captureResourceSnapshot{CPUMillis: float64(filetimeDuration(kernel)+filetimeDuration(user)) / float64(time.Millisecond), Private: private, Heap: m.HeapAlloc, HeapSys: m.HeapSys, Allocated: m.TotalAlloc, WorkingSet: uint64(mem.WorkingSet), PeakWorkingSet: uint64(mem.PeakWorkingSet)}
}
