//go:build windows

package winengine

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// PROCESS_MEMORY_COUNTERS_EX. These supplement Go's runtime accounting: DLL
// state and mapped/native allocations are not all part of GOMEMLIMIT.
type processMemoryCounters struct {
	Size, PageFaults                               uint32
	PeakWorkingSet, WorkingSet                     uintptr
	QuotaPeakPaged, QuotaPaged, QuotaPeakNonPaged  uintptr
	QuotaNonPaged, Pagefile, PeakPagefile, Private uintptr
}

type ProcessMemory struct {
	PrivateBytes          uint64 `json:"privateBytes"`
	WorkingSetBytes       uint64 `json:"workingSetBytes"`
	PagedPoolBytes        uint64 `json:"pagedPoolBytes"`
	NonPagedPoolBytes     uint64 `json:"nonPagedPoolBytes"`
	PeakNonPagedPoolBytes uint64 `json:"peakNonPagedPoolBytes"`
}

func processMemory() (ProcessMemory, error) {
	var counters processMemoryCounters
	counters.Size = uint32(unsafe.Sizeof(counters))
	ok, _, err := windows.NewLazySystemDLL("psapi.dll").NewProc("GetProcessMemoryInfo").Call(
		uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&counters)), uintptr(counters.Size))
	if ok == 0 {
		return ProcessMemory{}, fmt.Errorf("read Windows process memory: %w", err)
	}
	return ProcessMemory{PrivateBytes: uint64(counters.Private), WorkingSetBytes: uint64(counters.WorkingSet),
		PagedPoolBytes: uint64(counters.QuotaPaged), NonPagedPoolBytes: uint64(counters.QuotaNonPaged),
		PeakNonPagedPoolBytes: uint64(counters.QuotaPeakNonPaged)}, nil
}

// PERFORMANCE_INFORMATION reports page counts, converted here to bytes.
// These counters distinguish global memory pressure from socket/port limits;
// WSAENOBUFS alone does not identify which resource was exhausted.
func systemResources() map[string]any {
	var native struct {
		Size                               uint32
		Commit, CommitLimit, CommitPeak    uintptr
		Physical, PhysicalAvailable, Cache uintptr
		Kernel, Paged, NonPaged, PageSize  uintptr
		Handles, Processes, Threads        uint32
	}
	native.Size = uint32(unsafe.Sizeof(native))
	ok, _, err := windows.NewLazySystemDLL("psapi.dll").NewProc("GetPerformanceInfo").Call(
		uintptr(unsafe.Pointer(&native)), uintptr(native.Size))
	if ok == 0 {
		return map[string]any{"error": err.Error()}
	}
	result := map[string]any{
		"commitBytes":            uint64(native.Commit) * uint64(native.PageSize),
		"commitLimitBytes":       uint64(native.CommitLimit) * uint64(native.PageSize),
		"physicalBytes":          uint64(native.Physical) * uint64(native.PageSize),
		"physicalAvailableBytes": uint64(native.PhysicalAvailable) * uint64(native.PageSize),
		"pagedPoolBytes":         uint64(native.Paged) * uint64(native.PageSize),
		"nonPagedPoolBytes":      uint64(native.NonPaged) * uint64(native.PageSize),
		"systemHandles":          native.Handles, "processes": native.Processes, "threads": native.Threads,
	}
	var handles uint32
	ok, _, err = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessHandleCount").Call(
		uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&handles)))
	if ok == 0 {
		result["processHandleError"] = err.Error()
	} else {
		result["processHandles"] = handles
	}
	return result
}
