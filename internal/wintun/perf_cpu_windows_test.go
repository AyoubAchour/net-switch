//go:build windows

package wintun

import (
	"errors"
	"os"
	"runtime"
	"runtime/metrics"
	"sort"
	"sync/atomic"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

var performanceChildCPU atomic.Uint64
var systemTimes = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetSystemTimes")

type cpuProcess struct {
	name             string
	created, elapsed uint64
}

type cpuSample struct {
	qpc                               int64
	stamp, idle, kernel, user, child   uint64
	scheduler, slowScheduler, slowGC   uint64
	unreadable                        int
	processes                         map[uint32]cpuProcess
}

func fileTicks(t windows.Filetime) uint64 {
	return uint64(t.HighDateTime)<<32 | uint64(t.LowDateTime)
}

func captureCPU(t *testing.T) cpuSample {
	t.Helper()
	s := cpuSample{qpc: ticks(), child: performanceChildCPU.Load(), processes: make(map[uint32]cpuProcess)}
	var idle, kernel, user, stamp windows.Filetime
	windows.GetSystemTimeAsFileTime(&stamp)
	ok, _, err := systemTimes.Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user)))
	if ok == 0 {
		t.Fatal(err)
	}
	s.stamp, s.idle, s.kernel, s.user = fileTicks(stamp), fileTicks(idle), fileTicks(kernel), fileTicks(user)
	h, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	must(t, err)
	defer windows.CloseHandle(h)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	err = windows.Process32First(h, &entry)
	for err == nil {
		if entry.ProcessID != 0 {
			process, openErr := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, entry.ProcessID)
			if openErr == nil {
				var created, exited, kernel, user windows.Filetime
				queryErr := windows.GetProcessTimes(process, &created, &exited, &kernel, &user)
				windows.CloseHandle(process)
				if queryErr == nil {
					s.processes[entry.ProcessID] = cpuProcess{windows.UTF16ToString(entry.ExeFile[:]), fileTicks(created), fileTicks(kernel) + fileTicks(user)}
				} else {
					s.unreadable++
				}
			} else {
				s.unreadable++
			}
		}
		err = windows.Process32Next(h, &entry)
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		t.Fatal(err)
	}
	samples := []metrics.Sample{{Name: "/sched/latencies:seconds"}, {Name: "/gc/pauses:seconds"}}
	metrics.Read(samples)
	for i, sample := range samples {
		hist := sample.Value.Float64Histogram()
		for bucket, count := range hist.Counts {
			if i == 0 {
				s.scheduler += count
			}
			if hist.Buckets[bucket] >= 0.001 {
				if i == 0 {
					s.slowScheduler += count
				} else {
					s.slowGC += count
				}
			}
		}
	}
	return s
}

func reportCPU(t *testing.T, mode, metric string, trial int, before, after cpuSample) {
	type processCPU struct {
		Name    string  `json:"name"`
		Seconds float64 `json:"seconds"`
	}
	var others []processCPU
	var own float64
	for pid, p := range after.processes {
		old, found := before.processes[pid]
		if found && old.created != p.created {
			found = false
		}
		if !found && p.created < before.stamp {
			continue // Existing process was inaccessible at the first snapshot.
		}
		var prior uint64
		if found {
			prior = old.elapsed
		}
		seconds := float64(p.elapsed-prior) / 1e7
		if pid == uint32(os.Getpid()) {
			own = seconds
		} else if seconds > 0 {
			others = append(others, processCPU{p.name, seconds})
		}
	}
	sort.Slice(others, func(i, j int) bool { return others[i].Seconds > others[j].Seconds })
	if len(others) > 8 {
		others = others[:8]
	}
	idle := float64(after.idle-before.idle) / 1e7
	total := float64(after.kernel-before.kernel+after.user-before.user) / 1e7
	report(t, map[string]any{"test": "performance_cpu", "scope": "metric_including_fixed_warmups", "arch": runtime.GOARCH, "mode": mode, "trial": trial, "metric": metric,
		"wall_seconds": qpcDuration(before.qpc, after.qpc).Seconds(), "logical_cpus": runtime.NumCPU(), "system_active_seconds": total - idle, "system_idle_seconds": idle, "system_total_seconds": total,
		"self_cpu_seconds": own, "child_cpu_seconds": float64(after.child-before.child) / 1e9, "other_processes": others,
		"unreadable_processes_before": before.unreadable, "unreadable_processes_after": after.unreadable,
		"scheduler_samples": after.scheduler - before.scheduler, "scheduler_ge_1ms": after.slowScheduler - before.slowScheduler, "gc_pauses_ge_1ms": after.slowGC - before.slowGC})
}
