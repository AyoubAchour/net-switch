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
	PrivateBytes    uint64 `json:"privateBytes"`
	WorkingSetBytes uint64 `json:"workingSetBytes"`
}

func processMemory() (ProcessMemory, error) {
	var counters processMemoryCounters
	counters.Size = uint32(unsafe.Sizeof(counters))
	ok, _, err := windows.NewLazySystemDLL("psapi.dll").NewProc("GetProcessMemoryInfo").Call(
		uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&counters)), uintptr(counters.Size))
	if ok == 0 {
		return ProcessMemory{}, fmt.Errorf("read Windows process memory: %w", err)
	}
	return ProcessMemory{uint64(counters.Private), uint64(counters.WorkingSet)}, nil
}
